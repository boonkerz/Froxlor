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

use Froxlor\Database\Database;
use PDO;

class DatabaseDataSource implements DataSource
{
	public function getDomains(): array
	{
		$stmt = Database::query("
			SELECT d.`id`, d.`domain`, d.`isemaildomain`, d.`aliasdomain`, d.`parentdomainid`,
				d.`deactivated`, d.`email_only`, d.`letsencrypt`, d.`ssl_enabled`, d.`iswildcarddomain`,
				c.`deactivated` AS `customer_deactivated`
			FROM `" . TABLE_PANEL_DOMAINS . "` d
			LEFT JOIN `" . TABLE_PANEL_CUSTOMERS . "` c ON c.`customerid` = d.`customerid`
			ORDER BY d.`domain`
		");
		$result = [];
		while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$row['customer_deactivated'] = $row['customer_deactivated'] ?? 1;
			$result[] = $row;
		}
		return $result;
	}

	public function getCertificates(): array
	{
		$stmt = Database::query("
			SELECT `domainid`, `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file`, `ssl_cert_chainfile`, `ssl_fullchain_file`, `validtodate`
			FROM `" . TABLE_PANEL_DOMAIN_SSL_SETTINGS . "`
			WHERE `domainid` > 0 AND `ssl_cert_file` != ''
		");
		$result = [];
		while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
			$result[(int)$row['domainid']] = $row;
		}
		return $result;
	}
}
