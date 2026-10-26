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
 * checks whether a mail hostname can be validated via ACME (HTTP-01) on this system
 */
interface HostnameChecker
{
	/**
	 * @return string[] A/AAAA addresses of the hostname, null on lookup failure
	 */
	public function resolve(string $hostname): ?array;

	/**
	 * @return string[]|null MX hostnames of the domain (empty if none), null on lookup failure
	 */
	public function mx(string $domain): ?array;

	/**
	 * can the hostname serve an ACME HTTP-01 challenge from froxlor's challenge directory?
	 */
	public function challengeReachable(string $hostname): bool;
}
