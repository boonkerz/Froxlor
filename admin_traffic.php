<?php

/**
 * This file is part of the Froxlor project.
 * Copyright (c) 2003-2009 the SysCP Team (see authors).
 * Copyright (c) 2010 the Froxlor Team (see authors).
 *
 * For the full copyright and license information, please view the COPYING
 * file that was distributed with this source code. You can also view the
 * COPYING file online at http://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright  (c) the authors
 * @author     Morton Jonuschat <m.jonuschat@chrome-it.de>
 * @license    GPLv2 http://files.syscp.org/misc/COPYING.txt
 * @package    Panel
 *
 */

const AREA = 'admin';
require __DIR__ . '/lib/init.php';

use Froxlor\Database\Database;
use Froxlor\Settings;
use Froxlor\UI\Panel\UI;
use Froxlor\UI\Request;

$id = (int) Request::get('id');

$months = array(
	'0' => 'empty',
	'1' => 'jan',
	'2' => 'feb',
	'3' => 'mar',
	'4' => 'apr',
	'5' => 'may',
	'6' => 'jun',
	'7' => 'jul',
	'8' => 'aug',
	'9' => 'sep',
	'10' => 'oct',
	'11' => 'nov',
	'12' => 'dec'
);

if ($page == 'overview' || $page == 'customers') {
	$minyear_stmt = Database::query("SELECT `year` FROM `" . TABLE_PANEL_TRAFFIC . "` ORDER BY `year` ASC LIMIT 1");
	$minyear = $minyear_stmt->fetch(PDO::FETCH_ASSOC);

	if (! isset($minyear['year']) || $minyear['year'] == 0) {
		$maxyears = 0;
	} else {
		$maxyears = date("Y") - $minyear['year'];
	}

	$params = [];
	if ($userinfo['customers_see_all'] == '0') {
		$params = [
			'id' => $userinfo['adminid']
		];
	}

	$customer_name_list_stmt = Database::prepare("
		SELECT `customerid`,`company`,`name`,`firstname`
		FROM `" . TABLE_PANEL_CUSTOMERS . "`
		WHERE `deactivated`='0'" . ($userinfo['customers_see_all'] ? '' : ' AND `adminid` = :id') . "
		ORDER BY name"
	);

	$traffic_list_stmt = Database::prepare("
		SELECT month, SUM(http+ftp_up+ftp_down+mail)*1024 AS traffic
		FROM `" . TABLE_PANEL_TRAFFIC . "`
		WHERE year = :year AND `customerid` = :id
		GROUP BY month ORDER BY month"
	);

	$stats = [];

	for ($years = 0; $years <= $maxyears; $years ++) {
		$totals = array(
			'jan' => 0,
			'feb' => 0,
			'mar' => 0,
			'apr' => 0,
			'may' => 0,
			'jun' => 0,
			'jul' => 0,
			'aug' => 0,
			'sep' => 0,
			'oct' => 0,
			'nov' => 0,
			'dec' => 0
		);

		Database::pexecute($customer_name_list_stmt, $params);

		$data = [];
		while ($customer_name = $customer_name_list_stmt->fetch(PDO::FETCH_ASSOC)) {
			$virtual_host = array(
				'name' => ($customer_name['company'] == '' ? $customer_name['name'] . ", " . $customer_name['firstname'] : $customer_name['company']),
				'customerid' => $customer_name['customerid'],
				'jan' => '-',
				'feb' => '-',
				'mar' => '-',
				'apr' => '-',
				'may' => '-',
				'jun' => '-',
				'jul' => '-',
				'aug' => '-',
				'sep' => '-',
				'oct' => '-',
				'nov' => '-',
				'dec' => '-'
			);

			Database::pexecute($traffic_list_stmt, array(
				'year' => (date("Y") - $years),
				'id' => $customer_name['customerid']
			));

			while ($traffic_month = $traffic_list_stmt->fetch(PDO::FETCH_ASSOC)) {
				$virtual_host[$months[(int) $traffic_month['month']]] = \Froxlor\PhpHelper::sizeReadable($traffic_month['traffic'], 'GiB', 'bi', '%01.' . (int) Settings::Get('panel.decimal_places') . 'f %s');
				$totals[$months[(int) $traffic_month['month']]] += $traffic_month['traffic'];
			}

			$data = $virtual_host;
		}
		$stats[] = [
			'year' => date("Y") - $years,
			'type' => $lng['traffic']['customer'],
			'data' => $data,
		];
	}

	UI::view('user/traffic.html.twig', [
		'stats' => $stats
	]);
}
