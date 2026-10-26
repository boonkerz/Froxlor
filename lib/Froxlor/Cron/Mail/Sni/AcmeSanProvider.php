<?php

/**
 * This file is part of the froxlor project.
 * Copyright (c) 2010 the froxlor Team (see authors).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, you can also view it online at
 * https://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  the authors
 * @author     froxlor team <team@froxlor.org>
 * @license    https://files.froxlor.org/misc/COPYING.txt GPLv2
 */


namespace Froxlor\Cron\Mail\Sni;

use Froxlor\Domain\Domain;
use Froxlor\FroxlorLogger;
use Throwable;

/**
 * Extends froxlor's Let's Encrypt handling (AcmeSh) by the mail hostnames of a domain,
 * e.g. mail.example.com is added as SAN to the certificate of example.com.
 *
 * A mail hostname is only requested if
 *  - the domain (or alias domain) is an active email domain in froxlor,
 *  - the hostname is not a froxlor domain of its own (which gets its own certificate),
 *  - it resolves (A/AAAA) to an IP address of this system,
 *  - the MX records of the domain do not point to external servers only, and
 *  - an HTTP-01 challenge for the hostname is reachable on this system.
 * If an issuance including mail hostnames fails, those hostnames are left out for
 * FAILURE_BACKOFF seconds so the web certificate itself is never blocked by them.
 */
class AcmeSanProvider
{
	const RECHECK_INTERVAL = 21600;
	const FAILURE_BACKOFF = 86400;
	const MAX_REISSUES_PER_RUN = 5;
	const REMOVE_AFTER_FAILURES = 2;

	private MailSniConfig $config;
	private DataSource $source;
	private HostnameChecker $checker;
	private SniLogger $logger;
	private string $stateFile;

	/**
	 * @var callable returns the ip addresses of a domain-id
	 */
	private $ipsOf;

	/**
	 * @var callable|null
	 */
	private $clock;

	private ?array $state = null;
	private ?array $domains = null;

	public function __construct(MailSniConfig $config, DataSource $source, HostnameChecker $checker, SniLogger $logger, string $stateFile, callable $ipsOf, ?callable $clock = null)
	{
		$this->config = $config;
		$this->source = $source;
		$this->checker = $checker;
		$this->logger = $logger;
		$this->stateFile = $stateFile;
		$this->ipsOf = $ipsOf;
		$this->clock = $clock;
	}

	/**
	 * @return self|null null if the feature (or its acme part) is disabled
	 */
	public static function createDefault(?FroxlorLogger $logger = null): ?self
	{
		try {
			MailSniConfig::ensureSettings();
			$config = MailSniConfig::fromSettings();
			if (!$config->isAcmeEnabled() || !empty($config->validatePaths())) {
				return null;
			}
			return new self(
				$config,
				new DatabaseDataSource(),
				new SystemHostnameChecker(),
				new FroxlorSniLogger($logger ?? FroxlorLogger::getInstanceOf()),
				$config->certPath() . 'acme-state.json',
				function (int $domainId): array {
					return Domain::getIpsOfDomain($domainId);
				}
			);
		} catch (Throwable $e) {
			return null;
		}
	}

	/**
	 * mail hostnames to add to a certificate request
	 *
	 * @param int $domainId id of the domain the certificate is requested for
	 * @param string[] $sans hostnames already part of the request (domain, www-alias, alias domains)
	 * @return string[]
	 */
	public function additionalSans(int $domainId, array $sans): array
	{
		$sans = array_values(array_map('strtolower', $sans));
		$bases = [];
		foreach ($this->getDomains() as $domain) {
			if (in_array(strtolower($domain['domain']), $sans, true)
				&& ((int)$domain['id'] === $domainId || (int)($domain['aliasdomain'] ?? 0) === $domainId)) {
				$bases[] = $domain;
			}
		}
		$result = [];
		$ourIps = null;
		foreach ($this->candidates($bases, $sans) as $hostname => $base) {
			if ($ourIps === null) {
				$ourIps = ($this->ipsOf)($domainId);
			}
			[$ok, $reason] = $this->check($hostname, $base, $ourIps, true);
			if ($ok) {
				$result[] = $hostname;
			} else {
				$this->logger->log(LOG_INFO, 'not adding ' . $hostname . ' to the certificate of ' . $sans[0] . ': ' . $reason);
			}
		}
		$this->saveState();
		return $result;
	}

	/**
	 * remember the outcome of a certificate request that contained mail hostnames
	 *
	 * @param string[] $hostnames mail hostnames which were part of the request
	 */
	public function reportIssueResult(array $hostnames, bool $success): void
	{
		if (empty($hostnames)) {
			return;
		}
		$this->loadState();
		foreach ($hostnames as $hostname) {
			if ($success) {
				$this->state[$hostname]['backoff_until'] = 0;
			} else {
				$this->state[$hostname]['backoff_until'] = $this->now() + self::FAILURE_BACKOFF;
			}
		}
		if (!$success) {
			$this->logger->log(LOG_WARNING, 'certificate request including ' . implode(', ', $hostnames) . ' failed - these hostnames will not be requested again before ' . gmdate('Y-m-d H:i', $this->now() + self::FAILURE_BACKOFF) . ' UTC');
		}
		$this->saveState();
	}

	/**
	 * find let's encrypt certificates whose mail hostnames have to be added (or removed because they
	 * can no longer be validated, which would otherwise break the renewal of the whole certificate)
	 * and trigger a re-issue for them
	 *
	 * @param callable $markForReissue function(int $domainId): void
	 * @return string[] domains which have been marked
	 */
	public function scheduleReissues(callable $markForReissue): array
	{
		$certificates = $this->source->getCertificates();
		$domains = $this->getDomains();
		$marked = [];
		foreach ($domains as $domain) {
			if (!self::isLetsEncryptMainDomain($domain)) {
				continue;
			}
			$id = (int)$domain['id'];
			if (!isset($certificates[$id]) || empty($certificates[$id]['validtodate'])) {
				// not issued yet or already waiting for (re-)issue
				continue;
			}
			$cert = CertificateInfo::fromSslRow($certificates[$id]);
			if (!$cert->isParsable()) {
				continue;
			}
			$names = $cert->dnsNames();

			$bases = [$domain];
			foreach ($domains as $alias) {
				if ((int)($alias['aliasdomain'] ?? 0) === $id && (int)($alias['letsencrypt'] ?? 0) === 1 && (int)($alias['iswildcarddomain'] ?? 0) === 0) {
					$bases[] = $alias;
				}
			}
			$native = [];
			foreach ($bases as $base) {
				$native[] = strtolower($base['domain']);
				$native[] = 'www.' . strtolower($base['domain']);
			}
			$add = [];
			$remove = [];
			$ourIps = null;
			foreach ($this->candidates($bases, $native) as $hostname => $base) {
				if ($ourIps === null) {
					$ourIps = ($this->ipsOf)($id);
				}
				[$ok, $reason] = $this->check($hostname, $base, $ourIps, false);
				$present = in_array($hostname, $names, true);
				if ($ok && !$present) {
					$add[] = $hostname;
				} elseif (!$ok && $present && ($this->state[$hostname]['fails'] ?? 0) >= self::REMOVE_AFTER_FAILURES && ($this->state[$hostname]['backoff_until'] ?? 0) <= $this->now()) {
					$remove[] = $hostname . ' (' . $reason . ')';
				}
			}
			if (empty($add) && empty($remove)) {
				continue;
			}
			if (count($marked) >= self::MAX_REISSUES_PER_RUN) {
				$this->logger->log(LOG_INFO, 'more certificates need mail hostnames - postponed to the next run');
				break;
			}
			$this->logger->log(LOG_NOTICE, 're-issuing certificate of ' . $domain['domain']
				. (!empty($add) ? ' to add ' . implode(', ', $add) : '')
				. (!empty($remove) ? ' to remove ' . implode(', ', $remove) : ''));
			$markForReissue($id);
			$marked[] = $domain['domain'];
		}
		$this->saveState();
		return $marked;
	}

	public static function isLetsEncryptMainDomain(array $domain): bool
	{
		return MailHostResolver::isActive($domain)
			&& (int)($domain['letsencrypt'] ?? 0) === 1
			&& (int)($domain['ssl_enabled'] ?? 0) === 1
			&& empty($domain['aliasdomain'])
			&& (int)($domain['iswildcarddomain'] ?? 0) === 0
			&& (int)($domain['email_only'] ?? 0) === 0;
	}

	/**
	 * @param array[] $bases domain rows the certificate is (or will be) issued for
	 * @param string[] $exclude hostnames which are part of the certificate anyway
	 * @return array hostname => base domain name
	 */
	private function candidates(array $bases, array $exclude): array
	{
		$existing = [];
		foreach ($this->getDomains() as $domain) {
			$existing[strtolower($domain['domain'])] = true;
		}
		$excluded = array_merge($exclude, $this->config->excludedHostnames());
		$result = [];
		foreach ($bases as $base) {
			if (!MailHostResolver::isActiveMailDomain($base)) {
				continue;
			}
			foreach ($this->config->hostnamesFor($base['domain']) as $hostname) {
				// own froxlor domain -> has its own certificate
				if (in_array($hostname, $excluded, true) || isset($existing[$hostname])) {
					continue;
				}
				$result[$hostname] = strtolower($base['domain']);
			}
		}
		return $result;
	}

	/**
	 * @return array{0:bool,1:string}
	 */
	private function check(string $hostname, string $base, array $ourIps, bool $fresh): array
	{
		$this->loadState();
		$now = $this->now();
		$st = $this->state[$hostname] ?? [];
		if (($st['backoff_until'] ?? 0) > $now) {
			return [false, 'a previous certificate request failed, waiting until ' . gmdate('Y-m-d H:i', $st['backoff_until']) . ' UTC'];
		}
		if (!$fresh && isset($st['checked']) && $now - $st['checked'] < self::RECHECK_INTERVAL) {
			return [(bool)$st['ok'], (string)($st['reason'] ?? '')];
		}

		$reason = '';
		$ourIps = self::normalizeIps($ourIps);
		$ips = $this->checker->resolve($hostname);
		if ($ips === null) {
			$reason = 'DNS lookup failed';
		} elseif (empty(array_intersect(self::normalizeIps($ips), $ourIps))) {
			$reason = 'does not resolve to an IP address of this system (' . (empty($ips) ? 'no A/AAAA record' : implode(', ', $ips)) . ')';
		} else {
			$mx = $this->checker->mx($base);
			if ($mx === null) {
				$reason = 'MX lookup of ' . $base . ' failed';
			} elseif (!empty($mx) && !$this->mxIsLocal($mx, $hostname, $ourIps)) {
				$reason = 'mail of ' . $base . ' is handled by external servers (MX: ' . implode(', ', $mx) . ')';
			} elseif (!$this->checker->challengeReachable($hostname)) {
				$reason = 'ACME HTTP-01 challenge is not reachable via http://' . $hostname . '/.well-known/acme-challenge/';
			}
		}
		$ok = $reason === '';
		$this->state[$hostname] = [
			'checked' => $now,
			'ok' => $ok,
			'reason' => $reason,
			'fails' => $ok ? 0 : (int)($st['fails'] ?? 0) + 1,
			'backoff_until' => (int)($st['backoff_until'] ?? 0),
		];
		return [$ok, $reason];
	}

	private function mxIsLocal(array $mx, string $hostname, array $ourIps): bool
	{
		foreach ($mx as $mxHost) {
			if ($mxHost === $hostname) {
				return true;
			}
			$ips = $this->checker->resolve($mxHost);
			if (!empty($ips) && !empty(array_intersect(self::normalizeIps($ips), $ourIps))) {
				return true;
			}
		}
		return false;
	}

	private static function normalizeIps(array $ips): array
	{
		$result = [];
		foreach ($ips as $ip) {
			$packed = @inet_pton(trim($ip, '[] '));
			if ($packed !== false) {
				$result[] = inet_ntop($packed);
			}
		}
		return $result;
	}

	private function getDomains(): array
	{
		if ($this->domains === null) {
			$this->domains = $this->source->getDomains();
		}
		return $this->domains;
	}

	private function loadState(): void
	{
		if ($this->state !== null) {
			return;
		}
		$this->state = [];
		if (is_file($this->stateFile)) {
			$data = json_decode((string)@file_get_contents($this->stateFile), true);
			if (is_array($data)) {
				$this->state = $data;
			}
		}
	}

	private function saveState(): void
	{
		if ($this->state === null) {
			return;
		}
		// forget hostnames not checked for a long time
		foreach ($this->state as $hostname => $st) {
			if (($st['checked'] ?? 0) < $this->now() - 30 * 86400 && ($st['backoff_until'] ?? 0) < $this->now()) {
				unset($this->state[$hostname]);
			}
		}
		try {
			(new CertificateStore(dirname($this->stateFile)))->ensureDirectory();
			FileTransaction::atomicWrite($this->stateFile, json_encode($this->state, JSON_PRETTY_PRINT), 0600);
		} catch (Throwable $e) {
			$this->logger->log(LOG_WARNING, 'could not save ' . $this->stateFile . ': ' . $e->getMessage());
		}
	}

	private function now(): int
	{
		return $this->clock !== null ? (int)call_user_func($this->clock) : time();
	}
}
