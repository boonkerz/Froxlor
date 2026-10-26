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
 * one SNI hostname and the certificate that will be served for it
 */
class SniEntry
{
	public string $hostname;
	public string $domain;
	public int $certDomainId;
	public string $certDomain;
	public CertificateInfo $certificate;

	public function __construct(string $hostname, string $domain, int $certDomainId, string $certDomain, CertificateInfo $certificate)
	{
		$this->hostname = $hostname;
		$this->domain = $domain;
		$this->certDomainId = $certDomainId;
		$this->certDomain = $certDomain;
		$this->certificate = $certificate;
	}

	public function keyFile(string $certPath): string
	{
		return $certPath . $this->hostname . '.key';
	}

	public function fullchainFile(string $certPath): string
	{
		return $certPath . $this->hostname . '_fullchain.pem';
	}

	/**
	 * comment line documenting the deployed certificate; contains the fingerprint
	 * so that a renewed certificate (same paths, new content) changes the generated config
	 */
	public function describe(): string
	{
		return $this->hostname . ': sha256=' . $this->certificate->fingerprint()
			. ' valid-until=' . gmdate('Y-m-d\TH:i:s\Z', $this->certificate->validTo())
			. ' source=' . $this->certDomain;
	}
}
