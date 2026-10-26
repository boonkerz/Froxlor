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

/**
 * determines for every mail hostname (e.g. mail.example.com of every active
 * email-domain) the certificate froxlor already manages which covers it.
 *
 * Lookup order per hostname:
 *  1. a froxlor domain with exactly that name (e.g. a subdomain "mail.example.com" with its own certificate)
 *  2. the email domain itself (e.g. the let's encrypt certificate of example.com with mail.example.com as SAN)
 *  3. the domain the email domain is an alias of
 *  4. the parent domain (wildcard certificates)
 */
class MailHostResolver
{
	private MailSniConfig $config;

	/**
	 * hostname => reason why no SNI entry is generated
	 */
	private array $skipped = [];

	public function __construct(MailSniConfig $config)
	{
		$this->config = $config;
	}

	/**
	 * @return SniEntry[] indexed by hostname, sorted by hostname
	 */
	public function resolve(array $domains, array $certificates, ?int $now = null): array
	{
		$now = $now ?? time();
		$this->skipped = [];
		$byId = [];
		$byName = [];
		foreach ($domains as $domain) {
			$byId[(int)$domain['id']] = $domain;
			$byName[strtolower($domain['domain'])] = $domain;
		}
		$excluded = $this->config->excludedHostnames();
		$parsed = [];

		$entries = [];
		foreach ($domains as $domain) {
			if (!self::isActiveMailDomain($domain)) {
				continue;
			}
			foreach ($this->config->hostnamesFor($domain['domain']) as $hostname) {
				if (isset($entries[$hostname])) {
					continue;
				}
				if (in_array($hostname, $excluded, true)) {
					$this->skipped[$hostname] = 'is the system hostname (served by the default certificate)';
					continue;
				}
				$candidates = [];
				if (isset($byName[$hostname]) && self::isActive($byName[$hostname])) {
					$candidates[] = (int)$byName[$hostname]['id'];
				}
				$candidates[] = (int)$domain['id'];
				if (!empty($domain['aliasdomain'])) {
					$candidates[] = (int)$domain['aliasdomain'];
				}
				if (!empty($domain['parentdomainid'])) {
					$candidates[] = (int)$domain['parentdomainid'];
				}
				$reasons = [];
				foreach (array_unique($candidates) as $candidateId) {
					if (!isset($certificates[$candidateId]) || !isset($byId[$candidateId])) {
						continue;
					}
					if (!isset($parsed[$candidateId])) {
						$parsed[$candidateId] = CertificateInfo::fromSslRow($certificates[$candidateId]);
					}
					$cert = $parsed[$candidateId];
					$certDomain = $byId[$candidateId]['domain'];
					$problem = self::certificateProblem($cert, $hostname, $now);
					if ($problem !== null) {
						$reasons[] = 'certificate of ' . $certDomain . ' ' . $problem;
						continue;
					}
					$entries[$hostname] = new SniEntry($hostname, $domain['domain'], $candidateId, $certDomain, $cert);
					break;
				}
				if (!isset($entries[$hostname])) {
					$this->skipped[$hostname] = empty($reasons) ? 'no certificate available' : implode('; ', $reasons);
				}
			}
		}
		ksort($entries);
		ksort($this->skipped);
		return $entries;
	}

	/**
	 * @return string[] hostname => reason
	 */
	public function getSkipped(): array
	{
		return $this->skipped;
	}

	public static function isActive(array $domain): bool
	{
		return (int)($domain['deactivated'] ?? 0) === 0 && (int)($domain['customer_deactivated'] ?? 0) === 0;
	}

	public static function isActiveMailDomain(array $domain): bool
	{
		return self::isActive($domain) && (int)($domain['isemaildomain'] ?? 0) === 1;
	}

	public static function certificateProblem(CertificateInfo $cert, string $hostname, int $now): ?string
	{
		if (!$cert->isParsable()) {
			return 'cannot be parsed';
		}
		if (!$cert->covers($hostname)) {
			return 'does not cover ' . $hostname . ' (names: ' . implode(', ', $cert->dnsNames()) . ')';
		}
		if (!$cert->hasKey()) {
			return 'has no private key';
		}
		if (!$cert->keyMatches()) {
			return 'does not match its private key';
		}
		if (!$cert->isValidAt($now)) {
			return 'is expired or not yet valid (valid until ' . gmdate('Y-m-d H:i', $cert->validTo()) . ' UTC)';
		}
		return null;
	}
}
