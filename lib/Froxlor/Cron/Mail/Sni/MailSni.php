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

use Froxlor\FroxlorLogger;
use Throwable;

/**
 * Keeps the per-hostname TLS certificates of Postfix (tls_server_sni_maps) and
 * Dovecot (local_name) in sync with the certificates managed by froxlor.
 *
 * Called on every run of the tasks-cron, so domain changes, new or renewed certificates
 * and toggling the feature are picked up automatically. The run is idempotent: files are
 * only rewritten and services only reloaded if the generated content actually changed.
 */
class MailSni
{
	private MailSniConfig $config;
	private DataSource $source;
	private CommandRunner $runner;
	private SniLogger $logger;

	/**
	 * @var callable|null
	 */
	private $clock;

	public function __construct(MailSniConfig $config, DataSource $source, CommandRunner $runner, SniLogger $logger, ?callable $clock = null)
	{
		$this->config = $config;
		$this->source = $source;
		$this->runner = $runner;
		$this->logger = $logger;
		$this->clock = $clock;
	}

	/**
	 * create an instance using froxlor's settings, database and system log
	 */
	public static function createDefault(?FroxlorLogger $logger = null, ?SniLogger $sniLogger = null): self
	{
		MailSniConfig::ensureSettings();
		return new self(
			MailSniConfig::fromSettings(),
			new DatabaseDataSource(),
			new ProcessCommandRunner(),
			$sniLogger ?? new FroxlorSniLogger($logger ?? FroxlorLogger::getInstanceOf())
		);
	}

	/**
	 * @return array{enabled:bool, entries:SniEntry[], skipped:array, results:ServiceResult[], errors:string[]}
	 */
	public function sync(bool $dryRun = false): array
	{
		$report = ['enabled' => $this->config->isEnabled(), 'entries' => [], 'skipped' => [], 'results' => [], 'errors' => []];

		$pathErrors = $this->config->validatePaths();
		if (!empty($pathErrors)) {
			foreach ($pathErrors as $error) {
				$this->logger->log(LOG_ERR, 'invalid configuration: ' . $error);
			}
			$report['errors'] = $pathErrors;
			return $report;
		}

		$store = new CertificateStore($this->config->certPath());
		$postfix = $this->config->usePostfix() ? new PostfixSni($this->config, $this->runner, $this->logger, $this->backupBase()) : null;
		$dovecot = $this->config->useDovecot() ? new DovecotSni($this->config, $this->runner, $this->logger, $this->backupBase()) : null;

		if (!$this->config->isEnabled()) {
			// disabled: only clean up what this feature generated itself, never touch foreign files
			$postfix = $postfix !== null && $postfix->isManagedFile() ? $postfix : null;
			$dovecot = $dovecot !== null && $dovecot->isManagedFile() ? $dovecot : null;
			if ($postfix === null && $dovecot === null && (!is_dir($store->getPath()) || empty($store->deployedHostnames()))) {
				return $report;
			}
			$this->logger->log(LOG_INFO, 'feature disabled - removing generated SNI configuration');
		}

		if (!$dryRun && !$this->lock($store)) {
			$report['errors'][] = 'could not acquire lock (another mail-sni sync running?)';
			$this->logger->log(LOG_WARNING, 'could not acquire lock in ' . $store->getPath() . ' (another mail-sni sync running?), skipping');
			return $report;
		}
		try {
			return $this->doSync($report, $store, $postfix, $dovecot, $dryRun);
		} finally {
			$this->unlock();
		}
	}

	private function doSync(array $report, CertificateStore $store, ?PostfixSni $postfix, ?DovecotSni $dovecot, bool $dryRun): array
	{
		$entries = [];
		if ($this->config->isEnabled()) {
			$resolver = new MailHostResolver($this->config);
			try {
				$entries = $resolver->resolve($this->source->getDomains(), $this->source->getCertificates(), $this->now());
			} catch (Throwable $e) {
				$this->logger->log(LOG_ERR, 'could not read domains/certificates: ' . $e->getMessage());
				$report['errors'][] = $e->getMessage();
				return $report;
			}
			$report['skipped'] = $resolver->getSkipped();
			foreach ($report['skipped'] as $host => $reason) {
				$this->logger->log(LOG_DEBUG, 'no SNI entry for ' . $host . ': ' . $reason);
			}
		}
		$report['entries'] = $entries;

		// deploy key/fullchain files (validated pairs only, see MailHostResolver)
		if (!$dryRun && !empty($entries)) {
			try {
				$changed = $store->deploy($entries);
				if (!empty($changed)) {
					$this->logger->log(LOG_INFO, 'deployed certificate files for: ' . implode(', ', $changed));
				}
			} catch (Throwable $e) {
				$this->logger->log(LOG_ERR, 'could not deploy certificate files: ' . $e->getMessage() . ' - live configuration left untouched');
				$report['errors'][] = $e->getMessage();
				return $report;
			}
		}

		$allOk = true;
		foreach ([$postfix, $dovecot] as $service) {
			if ($service === null) {
				continue;
			}
			try {
				$result = $service->apply($service->render($entries, $store->getPath()), $entries, $dryRun);
			} catch (Throwable $e) {
				$result = new ServiceResult($service instanceof PostfixSni ? 'postfix' : 'dovecot', ServiceResult::FAILED, $e->getMessage());
			}
			$report['results'][$result->service] = $result;
			$allOk = $allOk && $result->isOk();
			$this->logResult($result);
			if ($result->isOk() && $result->reloadRequired && !$dryRun) {
				$this->reload($result->service);
			}
		}

		// only remove files of vanished hostnames once no (possibly restored) configuration references them anymore
		if (!$dryRun && $allOk) {
			$keep = array_merge(array_keys($entries), $this->referencedHostnames($store));
			$removed = $store->removeStale($keep);
			if (!empty($removed)) {
				$this->logger->log(LOG_INFO, 'removed certificate files of: ' . implode(', ', $removed));
			}
		}
		return $report;
	}

	/**
	 * hostnames whose store files are still referenced by a (foreign) postfix/dovecot file
	 *
	 * @return string[]
	 */
	private function referencedHostnames(CertificateStore $store): array
	{
		$hosts = [];
		foreach ([$this->config->postfixMap(), $this->config->dovecotConf()] as $file) {
			$content = is_file($file) ? (string)@file_get_contents($file) : '';
			if ($content !== '' && preg_match_all('#' . preg_quote($store->getPath(), '#') . '([a-z0-9.-]+)(?:\.key|_fullchain\.pem)#', $content, $m)) {
				$hosts = array_merge($hosts, $m[1]);
			}
		}
		return array_values(array_unique($hosts));
	}

	private function reload(string $service): void
	{
		$setting = $service === 'postfix' ? 'system.mta_reload_command' : 'system.mda_reload_command';
		$cmd = $this->config->get($setting);
		if (preg_match('/\brestart\b/i', $cmd)) {
			$this->logger->log(LOG_WARNING, $setting . ' contains "restart" - a reload is sufficient and does not drop connections');
		}
		[$code, $out] = $this->runner->runConfigured($cmd);
		if ($code === 0) {
			$this->logger->log(LOG_INFO, $service . ' reloaded');
		} else {
			$this->logger->log(LOG_ERR, 'error while running `' . $cmd . '`: exit code (' . $code . ') ' . $out . ' - please check your system logs');
		}
	}

	private function logResult(ServiceResult $result): void
	{
		$level = [
			ServiceResult::FAILED => LOG_ERR,
			ServiceResult::UPDATED => LOG_NOTICE,
			ServiceResult::DRYRUN => LOG_INFO,
		][$result->status] ?? LOG_DEBUG;
		$this->logger->log($level, $result->service . ': ' . $result->status . ($result->message !== '' ? ' - ' . trim($result->message) : ''));
	}

	private function backupBase(): string
	{
		return $this->config->certPath() . 'backups/';
	}

	/**
	 * @var resource|null
	 */
	private $lockHandle = null;

	private function lock(CertificateStore $store): bool
	{
		try {
			$store->ensureDirectory();
		} catch (Throwable $e) {
			$this->logger->log(LOG_ERR, $e->getMessage());
			return false;
		}
		$fh = @fopen($store->getPath() . '.lock', 'c');
		if ($fh === false) {
			return false;
		}
		if (!flock($fh, LOCK_EX | LOCK_NB)) {
			fclose($fh);
			return false;
		}
		$this->lockHandle = $fh;
		return true;
	}

	private function unlock(): void
	{
		if ($this->lockHandle !== null) {
			flock($this->lockHandle, LOCK_UN);
			fclose($this->lockHandle);
			$this->lockHandle = null;
		}
	}

	private function now(): int
	{
		return $this->clock !== null ? (int)call_user_func($this->clock) : time();
	}
}
