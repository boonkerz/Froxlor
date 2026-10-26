<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\DataSource;

class ArrayDataSource implements DataSource
{
	public array $domains = [];
	public array $certificates = [];

	public function addDomain(int $id, string $domain, array $extra = []): void
	{
		$this->domains[$id] = array_merge([
			'id' => $id,
			'domain' => $domain,
			'isemaildomain' => 1,
			'aliasdomain' => null,
			'parentdomainid' => 0,
			'deactivated' => 0,
			'customer_deactivated' => 0,
			'email_only' => 0,
			'letsencrypt' => 1,
			'ssl_enabled' => 1,
			'iswildcarddomain' => 0,
		], $extra);
	}

	public function getDomains(): array
	{
		return array_values($this->domains);
	}

	public function getCertificates(): array
	{
		return $this->certificates;
	}
}
