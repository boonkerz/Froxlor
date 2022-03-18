<?php
if (!defined('AREA')) {
	header("Location: index.php");
	exit();
}

/**
 * This file is part of the Froxlor project.
 * Copyright (c) 2016 the Froxlor Team (see authors).
 *
 * For the full copyright and license information, please view the COPYING
 * file that was distributed with this source code. You can also view the
 * COPYING file online at http://files.froxlor.org/misc/COPYING.txt
 *
 * @copyright (c) the authors
 * @author Froxlor team <team@froxlor.org> (2016-)
 * @license GPLv2 http://files.froxlor.org/misc/COPYING.txt
 * @package Panel
 *
 */

use Froxlor\Api\Commands\SubDomains;
use Froxlor\Settings;
use Froxlor\UI\Request;
use Froxlor\UI\Panel\UI;

// This file is being included in admin_domains and customer_domains
// and therefore does not need to require lib/init.php

$domain_id = (int) Request::get('domain_id');
$last_n = (int) Request::get('number_of_lines', 100);

// user's with logviewenabled = false
if (AREA != 'admin' && $userinfo['logviewenabled'] != '1') {
	// back to domain overview
	\Froxlor\UI\Response::redirectTo($filename, array(
		'page' => 'domains'
	));
}

if (function_exists('exec')) {

	// get domain-info
	try {
		$json_result = SubDomains::getLocal($userinfo, array(
			'id' => $domain_id
		))->get();
	} catch (Exception $e) {
		\Froxlor\UI\Response::dynamic_error($e->getMessage());
	}
	$domain = json_decode($json_result, true)['data'];

	$speciallogfile = '';
	if ($domain['speciallogfile'] == '1') {
		if ($domain['parentdomainid'] == '0') {
			$speciallogfile = '-' . $domain['domain'];
		} else {
			$speciallogfile = '-' . $domain['parentdomain'];
		}
	}
	// The normal access/error - logging is enabled
	$error_log = \Froxlor\FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . \Froxlor\Customer\Customer::getCustomerDetail($domain['customerid'], 'loginname') . $speciallogfile . '-error.log');
	$access_log = \Froxlor\FileDir::makeCorrectFile(Settings::Get('system.logfiles_directory') . \Froxlor\Customer\Customer::getCustomerDetail($domain['customerid'], 'loginname') . $speciallogfile . '-access.log');

	// error log
	if (file_exists($error_log)) {
		$result = \Froxlor\FileDir::safe_exec('tail -n ' . $last_n . ' ' . escapeshellarg($error_log));
		$error_log_content = implode("\n", $result);
	} else {
		$error_log_content = "Error-Log" . (AREA == 'admin' ? " '" . $error_log . "'" : "") . " does not seem to exist";
	}

	// access log
	if (file_exists($access_log)) {
		$result = \Froxlor\FileDir::safe_exec('tail -n ' . $last_n . ' ' . escapeshellarg($access_log));
		$access_log_content = implode("\n", $result);
	} else {
		$access_log_content = "Access-Log" . (AREA == 'admin' ? " '" . $access_log . "'" : "") . " does not seem to exist";
	}

	UI::view('user/logfiles.html.twig', [
		'error_log_content' => $error_log_content,
		'access_log_content' => $access_log_content,
		'actions_links' => [[
			'class' => 'btn-secondary',
			'href' => $linker->getLink(['section' => 'domains', 'page' => 'domains', 'action' => 'edit', 'id' => $domain_id]),
			'label' => $lng['panel']['edit'],
			'icon' => 'fa fa-pen'
		], [
			'class' => 'btn-secondary',
			'href' => $linker->getLink(['section' => 'domains', 'page' => 'domains']),
			'label' => $lng['menue']['domains']['domains'],
			'icon' => 'fa fa-globe'
		]]
	]);
} else {
	if (AREA == 'admin') {
		\Froxlor\UI\Response::dynamic_error('You need to allow the exec() function in the froxlor-vhost php-config');
	} else {
		\Froxlor\UI\Response::dynamic_error('Required function exec() is not allowed. Please contact the system administrator.');
	}
}
