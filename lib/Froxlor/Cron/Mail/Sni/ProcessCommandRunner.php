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
 * runs commands via proc_open() without a shell for internal commands
 */
class ProcessCommandRunner implements CommandRunner
{
	const PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

	public function run(array $argv): array
	{
		$argv = array_values(array_map('strval', $argv));
		if (empty($argv)) {
			return [127, 'empty command'];
		}
		$binary = $this->which($argv[0]);
		if ($binary === null) {
			return [127, $argv[0] . ': command not found'];
		}
		$argv[0] = $binary;
		// array command: no shell involved (PHP >= 7.4)
		$proc = @proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, [
			'PATH' => self::PATH,
			'LANG' => 'C',
			'LC_ALL' => 'C'
		]);
		if (!is_resource($proc)) {
			return [127, 'could not execute ' . $argv[0]];
		}
		fclose($pipes[0]);
		$out = stream_get_contents($pipes[1]);
		$err = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$code = proc_close($proc);
		return [(int)$code, trim($out . ($err !== '' ? "\n" . $err : ''))];
	}

	public function runConfigured(string $command): array
	{
		$command = trim($command);
		// same restrictions as froxlor's other *_reload_command settings
		if ($command === '' || !preg_match('/^[a-z0-9\/\._\- ]+$/i', $command)) {
			return [126, 'invalid command "' . $command . '"'];
		}
		return $this->run(preg_split('/\s+/', $command));
	}

	private function which(string $binary): ?string
	{
		if (strpos($binary, '/') !== false) {
			return is_executable($binary) ? $binary : null;
		}
		foreach (explode(':', self::PATH) as $dir) {
			if (is_executable($dir . '/' . $binary)) {
				return $dir . '/' . $binary;
			}
		}
		return null;
	}
}
