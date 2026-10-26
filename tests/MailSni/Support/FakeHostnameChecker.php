<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\HostnameChecker;

class FakeHostnameChecker implements HostnameChecker
{
	public array $a = [];
	public array $mx = [];
	public array $reachable = [];
	public int $lookups = 0;

	public function resolve(string $hostname): ?array
	{
		$this->lookups++;
		return array_key_exists($hostname, $this->a) ? $this->a[$hostname] : [];
	}

	public function mx(string $domain): ?array
	{
		return array_key_exists($domain, $this->mx) ? $this->mx[$domain] : [];
	}

	public function challengeReachable(string $hostname): bool
	{
		return $this->reachable[$hostname] ?? false;
	}
}
