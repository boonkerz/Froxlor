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
 * Postfix SNI table (tls_server_sni_maps, Postfix >= 3.4), e.g.
 *   mail.example.com /etc/ssl/froxlor-mail-sni/mail.example.com.key /etc/ssl/froxlor-mail-sni/mail.example.com_fullchain.pem
 *
 * The indexed table is built with "postmap -F", i.e. key and certificate chain are embedded
 * (base64) into the .db file - which is therefore created with mode 0600.
 */
class PostfixSni
{
	const MARKER = '# froxlor mail-sni: generated file';

	const TABLE_SUFFIX = [
		'hash' => '.db',
		'btree' => '.db',
		'lmdb' => '.lmdb',
		'cdb' => '.cdb',
	];

	private MailSniConfig $config;
	private CommandRunner $runner;
	private SniLogger $logger;
	private string $backupBase;

	public function __construct(MailSniConfig $config, CommandRunner $runner, SniLogger $logger, string $backupBase)
	{
		$this->config = $config;
		$this->runner = $runner;
		$this->logger = $logger;
		$this->backupBase = $backupBase;
	}

	/**
	 * @param SniEntry[] $entries
	 */
	public function render(array $entries, string $certPath): string
	{
		$out = self::MARKER . "\n";
		$out .= "# Do NOT edit manually - all changes will be overwritten by froxlor.\n";
		$out .= "# Rebuild: bin/froxlor-cli froxlor:mail-sni sync\n";
		foreach ($entries as $entry) {
			$out .= "\n# " . $entry->describe() . "\n";
			$out .= $entry->hostname . ' ' . $entry->keyFile($certPath) . ' ' . $entry->fullchainFile($certPath) . "\n";
		}
		return $out;
	}

	public function isManagedFile(): bool
	{
		$file = $this->config->postfixMap();
		return is_file($file) && strpos((string)@file_get_contents($file, false, null, 0, 256), self::MARKER) === 0;
	}

	/**
	 * @param SniEntry[] $entries
	 */
	public function apply(string $content, array $entries, bool $dryRun = false): ServiceResult
	{
		$map = $this->config->postfixMap();
		if (!is_dir(dirname($map))) {
			return new ServiceResult('postfix', ServiceResult::FAILED, 'directory ' . dirname($map) . ' does not exist');
		}

		[$code, $version] = $this->runner->run(['postconf', '-h', 'mail_version']);
		if ($code !== 0) {
			return new ServiceResult('postfix', ServiceResult::FAILED, 'could not determine postfix version: ' . $version);
		}
		if (version_compare(trim($version), '3.4', '<')) {
			return new ServiceResult('postfix', ServiceResult::FAILED, 'postfix ' . trim($version) . ' does not support "postmap -F" / tls_server_sni_maps (>= 3.4 required)');
		}

		[$code, $param] = $this->runner->run(['postconf', '-h', 'tls_server_sni_maps']);
		if ($code !== 0) {
			return new ServiceResult('postfix', ServiceResult::FAILED, 'could not read tls_server_sni_maps: ' . $param);
		}
		[$paramState, $type] = self::analyzeParameter(trim($param), $map);
		if (!isset(self::TABLE_SUFFIX[$type])) {
			return new ServiceResult('postfix', ServiceResult::FAILED, 'unsupported table type "' . $type . '" in tls_server_sni_maps');
		}
		$dbFile = $map . self::TABLE_SUFFIX[$type];
		$setParam = ($paramState === 'empty' && !empty($entries));

		$current = is_file($map) ? (string)file_get_contents($map) : null;
		$upToDate = $current === $content && is_file($dbFile) && filemtime($dbFile) >= filemtime($map);
		if ($upToDate && !$setParam) {
			return new ServiceResult('postfix', ServiceResult::UNCHANGED, $this->parameterNote($paramState, $param));
		}
		if ($dryRun) {
			return new ServiceResult('postfix', ServiceResult::DRYRUN, ($upToDate ? '' : $map . ' would be rebuilt (' . count($entries) . ' entries)') . ($setParam ? ' tls_server_sni_maps would be set to ' . $type . ':' . $map : ''));
		}

		// 1. build the new table next to the live one
		$tmp = FileTransaction::tempName($map);
		$tmpDb = $tmp . self::TABLE_SUFFIX[$type];
		@unlink($tmp);
		@unlink($tmpDb);
		try {
			FileTransaction::atomicWrite($tmp, $content, 0600);
			$old = umask(0077);
			try {
				[$code, $out] = $this->runner->run(['postmap', '-F', $type . ':' . $tmp]);
			} finally {
				umask($old);
			}
			if ($code !== 0 || !is_file($tmpDb)) {
				throw new RuntimeException('postmap -F failed: ' . $out);
			}
			chmod($tmpDb, 0600);

			// 2. validate every entry of the new table (the output contains the private key, never log it)
			foreach ($entries as $entry) {
				[$code, $out] = $this->runner->run(['postmap', '-F', '-q', $entry->hostname, $type . ':' . $tmp]);
				$valid = $code === 0 && strpos($out, 'PRIVATE KEY-----') !== false && strpos($out, '-----BEGIN CERTIFICATE-----') !== false;
				$out = null;
				if (!$valid) {
					throw new RuntimeException('validation of the new table failed for ' . $entry->hostname);
				}
			}
		} catch (RuntimeException $e) {
			@unlink($tmp);
			@unlink($tmpDb);
			return new ServiceResult('postfix', ServiceResult::FAILED, $e->getMessage() . ' - live configuration left untouched');
		}

		// 3. activate (backup + atomic rename), then "postfix check"; roll back on any error
		$tx = new FileTransaction($this->backupBase);
		try {
			$tx->save($map);
			$tx->save($dbFile);
			$mainCf = null;
			if ($setParam) {
				[$code, $configDir] = $this->runner->run(['postconf', '-h', 'config_directory']);
				$mainCf = rtrim(trim($configDir), '/') . '/main.cf';
				if ($code !== 0 || !is_file($mainCf)) {
					throw new RuntimeException('could not locate main.cf');
				}
				$tx->save($mainCf);
			}
			if (!rename($tmpDb, $dbFile) || !rename($tmp, $map)) {
				throw new RuntimeException('could not move new table into place');
			}
			if ($setParam) {
				[$code, $out] = $this->runner->run(['postconf', '-e', 'tls_server_sni_maps=' . $type . ':' . $map]);
				if ($code !== 0) {
					throw new RuntimeException('postconf -e failed: ' . $out);
				}
				$this->logger->log(LOG_NOTICE, 'set postfix parameter tls_server_sni_maps = ' . $type . ':' . $map . ' (backup of main.cf in ' . $tx->getBackupDirName() . ')');
			}
			[$code, $out] = $this->runner->run(['postfix', 'check']);
			if ($code !== 0) {
				throw new RuntimeException('"postfix check" failed: ' . $out);
			}
			if (trim($out) !== '') {
				$this->logger->log(LOG_WARNING, '"postfix check" reported: ' . $out);
			}
		} catch (RuntimeException $e) {
			@unlink($tmp);
			@unlink($tmpDb);
			$restored = $tx->rollback();
			return new ServiceResult('postfix', ServiceResult::FAILED, $e->getMessage() . ' - restored: ' . (empty($restored) ? 'nothing' : implode(', ', $restored)));
		}
		$tx->commit();
		$backup = $tx->getBackupDirName();
		return new ServiceResult(
			'postfix',
			ServiceResult::UPDATED,
			$map . ' rebuilt with ' . count($entries) . ' entries' . ($backup ? ' (backup: ' . $backup . ')' : '') . $this->parameterNote($paramState, $param),
			$paramState !== 'foreign'
		);
	}

	/**
	 * @return array{0:string,1:string} [state (ours|empty|foreign), table type]
	 */
	public static function analyzeParameter(string $param, string $map): array
	{
		if ($param === '') {
			return ['empty', 'hash'];
		}
		foreach (preg_split('/[\s,]+/', $param) as $table) {
			if (preg_match('/^([a-z0-9_]+):(.+)$/', $table, $m) && $m[2] === $map) {
				return ['ours', $m[1]];
			}
		}
		return ['foreign', 'hash'];
	}

	private function parameterNote(string $state, string $param): string
	{
		if ($state === 'foreign') {
			return ' - NOTE: tls_server_sni_maps is set to "' . trim($param) . '" which does not reference ' . $this->config->postfixMap() . ', the froxlor table is NOT active';
		}
		return '';
	}
}
