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
 * deploys key + fullchain of every SNI hostname into a dedicated, root-only directory:
 *   <mail.sni_cert_path>/<hostname>.key            (0600)
 *   <mail.sni_cert_path>/<hostname>_fullchain.pem  (0644)
 * Files are written atomically and only if their content changed.
 */
class CertificateStore
{
	private string $path;

	public function __construct(string $path)
	{
		$this->path = rtrim($path, '/') . '/';
	}

	public function getPath(): string
	{
		return $this->path;
	}

	public function ensureDirectory(): void
	{
		if (!is_dir($this->path)) {
			$old = umask(0077);
			$ok = @mkdir($this->path, 0700, true);
			umask($old);
			if (!$ok && !is_dir($this->path)) {
				throw new RuntimeException('could not create directory ' . $this->path);
			}
		}
		@chmod($this->path, 0700);
	}

	/**
	 * The files are derived from the database, so they are not backed up.
	 *
	 * @param SniEntry[] $entries
	 * @return string[] hostnames whose files have been (re-)written
	 */
	public function deploy(array $entries): array
	{
		$this->ensureDirectory();
		$changed = [];
		foreach ($entries as $entry) {
			$files = [
				[$entry->keyFile($this->path), $entry->certificate->keyPem(), 0600],
				[$entry->fullchainFile($this->path), $entry->certificate->fullchainPem(), 0644],
			];
			foreach ($files as [$file, $content, $mode]) {
				if (is_file($file) && @file_get_contents($file) === $content && (fileperms($file) & 0777) === $mode) {
					continue;
				}
				FileTransaction::atomicWrite($file, $content, $mode);
				$changed[$entry->hostname] = $entry->hostname;
			}
		}
		return array_values($changed);
	}

	/**
	 * hostnames which currently have files in the store
	 *
	 * @return string[]
	 */
	public function deployedHostnames(): array
	{
		$hosts = [];
		foreach (glob($this->path . '*.key') ?: [] as $file) {
			$host = substr(basename($file), 0, -4);
			if (self::isHostname($host)) {
				$hosts[] = $host;
			}
		}
		foreach (glob($this->path . '*_fullchain.pem') ?: [] as $file) {
			$host = substr(basename($file), 0, -strlen('_fullchain.pem'));
			if (self::isHostname($host)) {
				$hosts[] = $host;
			}
		}
		$hosts = array_values(array_unique($hosts));
		sort($hosts);
		return $hosts;
	}

	/**
	 * remove files of hostnames which are not in the given list
	 *
	 * @param string[] $keep hostnames
	 * @return string[] removed hostnames
	 */
	public function removeStale(array $keep): array
	{
		$removed = [];
		foreach ($this->deployedHostnames() as $host) {
			if (in_array($host, $keep, true)) {
				continue;
			}
			@unlink($this->path . $host . '.key');
			@unlink($this->path . $host . '_fullchain.pem');
			$removed[] = $host;
		}
		return $removed;
	}

	public static function isHostname(string $host): bool
	{
		return (bool)preg_match('/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $host);
	}
}
