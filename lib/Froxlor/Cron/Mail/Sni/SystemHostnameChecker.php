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

use Froxlor\PhpHelper;
use Froxlor\Settings;
use Net_DNS2_Exception;
use Net_DNS2_Resolver;
use Net_DNS2_RR_MX;

class SystemHostnameChecker implements HostnameChecker
{
	private ?string $nameserver;
	private string $challengePath;

	public function __construct(?string $nameserver = null, ?string $challengePath = null)
	{
		$this->nameserver = $nameserver ?? (Settings::Get('system.le_domain_dnscheck_resolver') ?: null);
		$this->challengePath = $challengePath ?? (string)Settings::Get('system.letsencryptchallengepath');
	}

	public function resolve(string $hostname): ?array
	{
		$ips = PhpHelper::gethostbynamel6($hostname, true, $this->nameserver);
		return is_array($ips) ? $ips : [];
	}

	public function mx(string $domain): ?array
	{
		try {
			$resolver = new Net_DNS2_Resolver($this->nameserver ? ['nameservers' => [$this->nameserver]] : []);
			$hosts = [];
			foreach ($resolver->query($domain, 'MX')->answer as $rr) {
				if ($rr instanceof Net_DNS2_RR_MX) {
					$hosts[] = strtolower(rtrim($rr->exchange, '.'));
				}
			}
			return $hosts;
		} catch (Net_DNS2_Exception $e) {
			// NXDOMAIN / no data: no MX records; anything else is a lookup failure
			return $e->getCode() === 3 ? [] : null;
		}
	}

	public function challengeReachable(string $hostname): bool
	{
		$dir = rtrim($this->challengePath, '/') . '/.well-known/acme-challenge';
		if ($this->challengePath === '' || !is_dir($dir)) {
			return false;
		}
		$token = 'froxlor-mail-sni-' . bin2hex(random_bytes(16));
		$file = $dir . '/' . $token;
		if (@file_put_contents($file, $token) === false) {
			return false;
		}
		@chmod($file, 0644);
		try {
			// like the ACME server: plain http on port 80, redirects (also to https) are followed,
			// the certificate of a https-redirect target is not verified
			$context = stream_context_create([
				'http' => ['timeout' => 10, 'follow_location' => 1, 'max_redirects' => 5, 'ignore_errors' => false],
				'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
			]);
			$body = @file_get_contents('http://' . $hostname . '/.well-known/acme-challenge/' . $token, false, $context, 0, 1024);
			return is_string($body) && trim($body) === $token;
		} finally {
			@unlink($file);
		}
	}
}
