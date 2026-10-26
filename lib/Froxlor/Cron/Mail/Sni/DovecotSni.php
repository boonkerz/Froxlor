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

use RuntimeException;

/**
 * Dovecot SNI configuration (local_name blocks), Dovecot 2.3 and 2.4 syntax
 */
class DovecotSni
{
	const MARKER = '# froxlor mail-sni: generated file';

	private MailSniConfig $config;
	private CommandRunner $runner;
	private SniLogger $logger;
	private string $backupBase;
	private ?string $version = null;

	public function __construct(MailSniConfig $config, CommandRunner $runner, SniLogger $logger, string $backupBase)
	{
		$this->config = $config;
		$this->runner = $runner;
		$this->logger = $logger;
		$this->backupBase = $backupBase;
	}

	/**
	 * installed dovecot version, e.g. "2.3.16"
	 */
	public function getVersion(): string
	{
		if ($this->version === null) {
			[$code, $out] = $this->runner->run(['dovecot', '--version']);
			if ($code === 0 && preg_match('/^(\d+\.\d+(\.\d+)?)/', trim($out), $m)) {
				$this->version = $m[1];
			} else {
				// fall back to what the admin configured for the let's encrypt renew-hook
				$this->version = preg_match('/(^|,)\s*dovecot24\s*(,|$)/', $this->config->get('system.le_renew_services')) ? '2.4' : '2.3';
				$this->logger->log(LOG_WARNING, 'could not determine dovecot version, assuming ' . $this->version);
			}
		}
		return $this->version;
	}

	/**
	 * @param SniEntry[] $entries
	 */
	public function render(array $entries, string $certPath): string
	{
		$v24 = version_compare($this->getVersion(), '2.4', '>=');
		$out = self::MARKER . "\n";
		$out .= "# Do NOT edit manually - all changes will be overwritten by froxlor.\n";
		$out .= "# Rebuild: bin/froxlor-cli froxlor:mail-sni sync\n";
		foreach ($entries as $entry) {
			$out .= "\n# " . $entry->describe() . "\n";
			$out .= 'local_name ' . $entry->hostname . " {\n";
			if ($v24) {
				$out .= '  ssl_server_cert_file = ' . $entry->fullchainFile($certPath) . "\n";
				$out .= '  ssl_server_key_file = ' . $entry->keyFile($certPath) . "\n";
			} else {
				$out .= '  ssl_cert = <' . $entry->fullchainFile($certPath) . "\n";
				$out .= '  ssl_key = <' . $entry->keyFile($certPath) . "\n";
			}
			$out .= "}\n";
		}
		return $out;
	}

	public function isManagedFile(): bool
	{
		$file = $this->config->dovecotConf();
		return is_file($file) && strpos((string)@file_get_contents($file, false, null, 0, 256), self::MARKER) === 0;
	}

	/**
	 * @param SniEntry[] $entries
	 */
	public function apply(string $content, array $entries, bool $dryRun = false): ServiceResult
	{
		$conf = $this->config->dovecotConf();
		if (!is_dir(dirname($conf))) {
			return new ServiceResult('dovecot', ServiceResult::FAILED, 'directory ' . dirname($conf) . ' does not exist');
		}
		$current = is_file($conf) ? (string)file_get_contents($conf) : null;
		if ($current === $content) {
			return new ServiceResult('dovecot', ServiceResult::UNCHANGED);
		}
		if ($dryRun) {
			return new ServiceResult('dovecot', ServiceResult::DRYRUN, $conf . ' would be rewritten (' . count($entries) . ' local_name blocks)');
		}

		$tx = new FileTransaction($this->backupBase);
		try {
			$tx->save($conf);
			FileTransaction::atomicWrite($conf, $content, 0644);
			[$code, $out] = $this->runner->run(['doveconf', '-n']);
			if ($code !== 0) {
				throw new RuntimeException('"doveconf -n" failed: ' . self::firstLines($out));
			}
			if (!empty($entries)) {
				$first = reset($entries);
				if (strpos($out, 'local_name ' . $first->hostname . ' {') === false) {
					$this->logger->log(LOG_WARNING, $conf . ' does not seem to be included in the dovecot configuration (missing "!include conf.d/*.conf"?)');
				}
			}
		} catch (RuntimeException $e) {
			$restored = $tx->rollback();
			return new ServiceResult('dovecot', ServiceResult::FAILED, $e->getMessage() . ' - restored: ' . (empty($restored) ? 'nothing' : implode(', ', $restored)));
		}
		$tx->commit();
		$backup = $tx->getBackupDirName();
		return new ServiceResult(
			'dovecot',
			ServiceResult::UPDATED,
			$conf . ' written with ' . count($entries) . ' local_name blocks (dovecot ' . $this->getVersion() . ' syntax)' . ($backup ? ', backup: ' . $backup : ''),
			true
		);
	}

	private static function firstLines(string $out, int $lines = 5): string
	{
		return implode(' | ', array_slice(explode("\n", trim($out)), 0, $lines));
	}
}
