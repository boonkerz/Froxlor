<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\SniLogger;

class MemoryLogger implements SniLogger
{
	public array $messages = [];

	public function log(int $level, string $message): void
	{
		$this->messages[] = [$level, $message];
	}

	public function contains(string $needle, ?int $maxLevel = null): bool
	{
		foreach ($this->messages as [$level, $message]) {
			if (strpos($message, $needle) !== false && ($maxLevel === null || $level <= $maxLevel)) {
				return true;
			}
		}
		return false;
	}

	public function all(): string
	{
		return implode("\n", array_map(function ($m) {
			return $m[0] . ' ' . $m[1];
		}, $this->messages));
	}
}
