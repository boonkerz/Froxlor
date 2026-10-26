<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\CommandRunner;

/**
 * emulates postconf/postmap/postfix/doveconf/dovecot - no real service is touched
 */
class FakeRunner implements CommandRunner
{
	public array $calls = [];
	public array $configured = [];
	public string $postfixVersion = '3.6.4';
	public string $dovecotVersion = '2.3.16 (7e2e900c1a)';
	public string $sniMapsParam = 'hash:/etc/postfix/99-froxlor.map';
	public int $postfixCheckCode = 0;
	public int $doveconfCode = 0;
	public int $postmapCode = 0;
	public string $doveconfFile = '';
	public string $mainCf = '';

	public function run(array $argv): array
	{
		$this->calls[] = implode(' ', $argv);
		switch ($argv[0]) {
			case 'postconf':
				if ($argv[1] === '-h' && $argv[2] === 'mail_version') {
					return [0, $this->postfixVersion];
				}
				if ($argv[1] === '-h' && $argv[2] === 'tls_server_sni_maps') {
					return [0, $this->sniMapsParam];
				}
				if ($argv[1] === '-h' && $argv[2] === 'config_directory') {
					return [0, dirname($this->mainCf)];
				}
				if ($argv[1] === '-e') {
					$this->sniMapsParam = substr($argv[2], strlen('tls_server_sni_maps='));
					file_put_contents($this->mainCf, file_get_contents($this->mainCf) . $argv[2] . "\n");
					return [0, ''];
				}
				return [1, 'unknown'];
			case 'postmap':
				return $this->postmap($argv);
			case 'postfix':
				return [$this->postfixCheckCode, $this->postfixCheckCode === 0 ? '' : 'postfix/postfix-script: fatal: bad configuration'];
			case 'dovecot':
				return [0, $this->dovecotVersion];
			case 'doveconf':
				$content = is_file($this->doveconfFile) ? file_get_contents($this->doveconfFile) : '';
				return [$this->doveconfCode, $this->doveconfCode === 0 ? $content : 'doveconf: Fatal: Error in configuration file'];
		}
		return [127, 'not found'];
	}

	private function postmap(array $argv): array
	{
		if ($this->postmapCode !== 0) {
			return [$this->postmapCode, 'postmap: fatal: error'];
		}
		if ($argv[2] === '-q') {
			[$type, $file] = explode(':', $argv[4], 2);
			$db = json_decode((string)@file_get_contents($file . '.db'), true) ?: [];
			return isset($db[$argv[3]]) ? [0, $db[$argv[3]]] : [1, ''];
		}
		[$type, $file] = explode(':', $argv[2], 2);
		$db = [];
		foreach (file($file) as $line) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}
			$parts = preg_split('/\s+/', $line);
			$host = array_shift($parts);
			$db[$host] = implode('', array_map('file_get_contents', $parts));
		}
		file_put_contents($file . '.db', json_encode($db));
		return [0, ''];
	}

	public function runConfigured(string $command): array
	{
		$this->configured[] = $command;
		return [0, ''];
	}

	public function reloads(): array
	{
		return $this->configured;
	}
}
