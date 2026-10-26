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
 * atomic file replacement and backup/restore of the files managed by the mail-SNI feature
 */
class FileTransaction
{
	const BACKUP_RETENTION = 20;

	private string $backupBase;
	private ?string $backupDir = null;

	/**
	 * file => backup copy (or null if the file did not exist before)
	 */
	private array $saved = [];

	public function __construct(string $backupBase)
	{
		$this->backupBase = rtrim($backupBase, '/') . '/';
	}

	/**
	 * write content to a temporary file in the target directory and rename() it into place
	 */
	public static function atomicWrite(string $file, string $content, int $mode = 0644): void
	{
		$dir = dirname($file);
		if (!is_dir($dir)) {
			throw new RuntimeException('directory ' . $dir . ' does not exist');
		}
		$tmp = self::tempName($file);
		$old = umask(0077);
		try {
			if (file_put_contents($tmp, $content, LOCK_EX) !== strlen($content)) {
				@unlink($tmp);
				throw new RuntimeException('could not write ' . $tmp);
			}
		} finally {
			umask($old);
		}
		chmod($tmp, $mode);
		if (!rename($tmp, $file)) {
			@unlink($tmp);
			throw new RuntimeException('could not move ' . $tmp . ' to ' . $file);
		}
	}

	public static function tempName(string $file): string
	{
		return dirname($file) . '/.' . basename($file) . '.froxlor-tmp-' . getmypid();
	}

	/**
	 * remember the current state of the given file (once per transaction) so it can be restored
	 */
	public function save(string $file): void
	{
		if (array_key_exists($file, $this->saved)) {
			return;
		}
		if (!file_exists($file)) {
			$this->saved[$file] = null;
			return;
		}
		$dir = $this->getBackupDir();
		$copy = $dir . str_replace('/', '_', ltrim($file, '/'));
		if (!copy($file, $copy)) {
			throw new RuntimeException('could not back up ' . $file);
		}
		chmod($copy, 0600);
		$this->saved[$file] = $copy;
	}

	/**
	 * restore all saved files to the state they had when save() was called
	 *
	 * @return string[] restored files
	 */
	public function rollback(): array
	{
		$restored = [];
		foreach ($this->saved as $file => $copy) {
			if ($copy === null) {
				if (file_exists($file)) {
					@unlink($file);
					$restored[] = $file;
				}
				continue;
			}
			$perms = fileperms($copy) & 0777;
			$tmp = self::tempName($file);
			if (@copy($copy, $tmp)) {
				$orig_perms = @fileperms($file);
				chmod($tmp, $orig_perms !== false ? ($orig_perms & 0777) : $perms);
				@rename($tmp, $file);
				$restored[] = $file;
			}
		}
		$this->saved = [];
		return $restored;
	}

	public function commit(): void
	{
		$this->saved = [];
	}

	public function getBackupDirName(): ?string
	{
		return $this->backupDir;
	}

	private function getBackupDir(): string
	{
		if ($this->backupDir === null) {
			if (!is_dir($this->backupBase)) {
				$old = umask(0077);
				$ok = @mkdir($this->backupBase, 0700, true);
				umask($old);
				if (!$ok && !is_dir($this->backupBase)) {
					throw new RuntimeException('could not create backup directory ' . $this->backupBase);
				}
			}
			$name = gmdate('Ymd-His') . '-' . getmypid();
			$dir = $this->backupBase . $name . '/';
			$i = 0;
			while (file_exists($dir)) {
				$dir = $this->backupBase . $name . '-' . (++$i) . '/';
			}
			if (!@mkdir($dir, 0700)) {
				throw new RuntimeException('could not create backup directory ' . $dir);
			}
			$this->backupDir = $dir;
			$this->prune();
		}
		return $this->backupDir;
	}

	/**
	 * keep only the newest BACKUP_RETENTION backup directories
	 */
	private function prune(): void
	{
		$dirs = glob($this->backupBase . '[0-9]*-*', GLOB_ONLYDIR) ?: [];
		sort($dirs);
		while (count($dirs) > self::BACKUP_RETENTION) {
			$dir = array_shift($dirs);
			foreach (glob($dir . '/*') ?: [] as $f) {
				@unlink($f);
			}
			@rmdir($dir);
		}
	}
}
