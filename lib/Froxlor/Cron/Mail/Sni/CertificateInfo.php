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
 * Read-only view on a certificate (and optionally its private key / chain)
 * as stored by froxlor in panel_domain_ssl_settings.
 *
 * Never exposes the private key in any string representation.
 */
class CertificateInfo
{
	private string $certPem;
	private string $keyPem;
	private string $chainPem;
	private ?array $parsed;

	public function __construct(string $certPem, string $keyPem = '', string $chainPem = '')
	{
		$this->certPem = trim($certPem);
		$this->keyPem = trim($keyPem);
		$this->chainPem = trim($chainPem);
		$parsed = $this->certPem !== '' ? @openssl_x509_parse($this->certPem) : false;
		$this->parsed = is_array($parsed) ? $parsed : null;
	}

	/**
	 * build from a row of panel_domain_ssl_settings
	 */
	public static function fromSslRow(array $row): self
	{
		$cert = (string)($row['ssl_cert_file'] ?? '');
		$key = (string)($row['ssl_key_file'] ?? '');
		$fullchain = trim((string)($row['ssl_fullchain_file'] ?? ''));
		$chain = '';
		if ($fullchain !== '') {
			// let's encrypt: fullchain = cert + intermediates; strip the leaf to get the chain
			$chain = self::stripFirstCertificate($fullchain);
		} elseif (trim((string)($row['ssl_cert_chainfile'] ?? '')) !== '') {
			$chain = (string)$row['ssl_cert_chainfile'];
		} elseif (trim((string)($row['ssl_ca_file'] ?? '')) !== '') {
			$chain = (string)$row['ssl_ca_file'];
		}
		// a chain might accidentally contain the leaf certificate itself
		if ($chain !== '' && trim($cert) !== '' && strpos(self::normalizePem($chain), self::normalizePem(self::firstCertificate($cert))) !== false) {
			$chain = self::stripFirstCertificate($chain);
		}
		return new self(self::firstCertificate($cert), $key, $chain);
	}

	public function isParsable(): bool
	{
		return $this->parsed !== null;
	}

	public function hasKey(): bool
	{
		return $this->keyPem !== '';
	}

	public function keyMatches(): bool
	{
		if (!$this->isParsable() || !$this->hasKey()) {
			return false;
		}
		return @openssl_x509_check_private_key($this->certPem, $this->keyPem) === true;
	}

	public function validFrom(): int
	{
		return (int)($this->parsed['validFrom_time_t'] ?? 0);
	}

	public function validTo(): int
	{
		return (int)($this->parsed['validTo_time_t'] ?? 0);
	}

	public function isValidAt(int $time): bool
	{
		return $this->isParsable() && $this->validFrom() <= $time && $this->validTo() > $time;
	}

	public function subjectCn(): string
	{
		$cn = $this->parsed['subject']['CN'] ?? '';
		return is_array($cn) ? (string)reset($cn) : (string)$cn;
	}

	public function issuer(): string
	{
		$o = $this->parsed['issuer']['O'] ?? ($this->parsed['issuer']['CN'] ?? '');
		return is_array($o) ? (string)reset($o) : (string)$o;
	}

	/**
	 * DNS names of the certificate (subjectAltName, falls back to CN if no SAN present)
	 *
	 * @return string[]
	 */
	public function dnsNames(): array
	{
		$names = [];
		$san = $this->parsed['extensions']['subjectAltName'] ?? '';
		foreach (explode(',', (string)$san) as $entry) {
			$entry = trim($entry);
			if (stripos($entry, 'DNS:') === 0) {
				$names[] = strtolower(trim(substr($entry, 4)));
			}
		}
		if (empty($names) && $this->subjectCn() !== '') {
			$names[] = strtolower($this->subjectCn());
		}
		return array_values(array_unique($names));
	}

	/**
	 * RFC 6125 style match: exact name or a single-label wildcard (*.example.com)
	 */
	public function covers(string $hostname): bool
	{
		$hostname = strtolower(rtrim($hostname, '.'));
		foreach ($this->dnsNames() as $name) {
			if ($name === $hostname) {
				return true;
			}
			if (strpos($name, '*.') === 0) {
				$suffix = substr($name, 1);
				$pos = strpos($hostname, '.');
				if ($pos !== false && $pos > 0 && substr($hostname, $pos) === $suffix) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * sha256 fingerprint of the leaf certificate (used to detect renewals)
	 */
	public function fingerprint(): string
	{
		if (!$this->isParsable()) {
			return '';
		}
		$fp = @openssl_x509_fingerprint($this->certPem, 'sha256');
		return is_string($fp) ? strtolower($fp) : '';
	}

	/**
	 * leaf certificate followed by the intermediate chain
	 */
	public function fullchainPem(): string
	{
		$out = $this->certPem . "\n";
		if ($this->chainPem !== '') {
			$out .= $this->chainPem . "\n";
		}
		return $out;
	}

	public function keyPem(): string
	{
		return $this->keyPem === '' ? '' : $this->keyPem . "\n";
	}

	public function __toString(): string
	{
		return 'certificate CN=' . $this->subjectCn() . ' sha256=' . $this->fingerprint();
	}

	public function __debugInfo()
	{
		// make sure var_dump()/print_r() never leak the private key
		return [
			'cn' => $this->subjectCn(),
			'names' => $this->dnsNames(),
			'validTo' => $this->validTo(),
			'fingerprint' => $this->fingerprint(),
			'hasKey' => $this->hasKey(),
		];
	}

	private static function pemBlocks(string $pem): array
	{
		preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $m);
		return $m[0];
	}

	private static function firstCertificate(string $pem): string
	{
		$blocks = self::pemBlocks($pem);
		return $blocks[0] ?? trim($pem);
	}

	private static function stripFirstCertificate(string $pem): string
	{
		$blocks = self::pemBlocks($pem);
		array_shift($blocks);
		return implode("\n", $blocks);
	}

	private static function normalizePem(string $pem): string
	{
		return preg_replace('/\s+/', '', $pem);
	}
}
