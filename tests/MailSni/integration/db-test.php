<?php
/**
 * database test against a real MariaDB with the official froxlor 2.3.16 schema
 * (run by db-test.sh inside a throw-away copy of the repository)
 */
require 'vendor/autoload.php';
require 'lib/tables.inc.php';
require 'tests/MailSni/Support/TestCertificates.php';

use Froxlor\Cron\Mail\Sni\DatabaseDataSource;
use Froxlor\Cron\Mail\Sni\MailHostResolver;
use Froxlor\Cron\Mail\Sni\MailSniConfig;
use Froxlor\Database\Database;
use Froxlor\Froxlor;
use Froxlor\Settings;
use Froxlor\Settings\Store;
use Froxlor\Tests\MailSni\TestCertificates;

$fails = 0;
function check(bool $cond, string $msg)
{
	global $fails;
	echo ($cond ? 'PASS: ' : 'FAIL: ') . $msg . "\n";
	$fails += $cond ? 0 : 1;
}
function dbv()
{
	return Database::query("SELECT `value` FROM panel_settings WHERE settinggroup='panel' AND varname='db_version'")->fetchColumn();
}

// legacy rows as left behind by the old fork (DBVERSION 202402190) after the official update
Database::query("INSERT INTO panel_settings (settinggroup, varname, value) VALUES
	('system','mail_sni_enabled','1'), ('system','mda_conf_dir','/etc/dovecot/conf.d/'),
	('system','mda_reload_command','service dovecot restart')");
Settings::Stash();

$before = dbv();
check($before === Froxlor::DBVERSION && $before === '202608210', 'db_version is the official one (' . $before . ')');
$rows = (int)Database::query("SELECT COUNT(*) FROM panel_settings")->fetchColumn();

$added = MailSniConfig::ensureSettings();
check(!in_array('system.mda_reload_command', $added), 'existing setting is kept, not duplicated');
check(count($added) === 7, 'added ' . count($added) . ' missing settings: ' . implode(', ', $added));
check(dbv() === $before, 'db_version untouched after ensureSettings');
check(!Froxlor::hasDbUpdates() && !Froxlor::hasUpdates(), 'froxlor sees no pending update');
check(MailSniConfig::ensureSettings() === [], 'second call is a no-op');
$dupes = Database::query("SELECT settinggroup, varname, COUNT(*) c FROM panel_settings GROUP BY settinggroup, varname HAVING c > 1")->fetchAll();
check(empty($dupes), 'no duplicate settings rows');
check((int)Database::query("SELECT COUNT(*) FROM panel_settings")->fetchColumn() === $rows + 7, 'exactly 7 rows added, nothing deleted');
check(Settings::Get('system.mail_sni_enabled') === '1' && Settings::Get('mail.sni_enabled') === '0', 'legacy setting not adopted, feature starts disabled');

// saving via the settings form works (row exists / is created)
Database::query("DELETE FROM panel_settings WHERE settinggroup='mail' AND varname='sni_hostnames'");
Settings::Stash();
$fd = ['settinggroup' => 'mail', 'varname' => 'sni_hostnames'];
check(Store::storeSettingFieldMailSni('mail_sni_hostnames', $fd, 'mail,imap') !== false, 'storeSettingFieldMailSni stores even if row was missing');
check(Database::query("SELECT value FROM panel_settings WHERE settinggroup='mail' AND varname='sni_hostnames'")->fetchColumn() === 'mail,imap', 'value persisted');

// domains + certificates through the real SQL queries
Database::query("INSERT INTO panel_customers (customerid, loginname, password, name, firstname, email, deactivated, documentroot, guid) VALUES
	(1,'web1','x','A','B','a@b.c',0,'/var/customers/webs/web1/',10000), (2,'web2','x','A','B','a@c.c',1,'/var/customers/webs/web2/',10001)");
$ins = Database::prepare("INSERT INTO panel_domains (id, domain, customerid, adminid, isemaildomain, aliasdomain, parentdomainid, deactivated, letsencrypt, ssl_enabled, documentroot)
	VALUES (:id, :d, :c, 1, :m, :a, :p, :x, 1, 1, '/var/customers/webs/web1/')");
foreach ([[1, 'example.de', 1, 1, null, 0, 0], [2, 'alias.de', 1, 1, 1, 0, 0], [3, 'off.de', 1, 1, null, 0, 1], [4, 'cust-off.de', 2, 1, null, 0, 0], [5, 'nomail.de', 1, 0, null, 0, 0]] as $d) {
	Database::pexecute($ins, ['id' => $d[0], 'd' => $d[1], 'c' => $d[2], 'm' => $d[3], 'a' => $d[4], 'p' => $d[5], 'x' => $d[6]]);
}
$ssl = Database::prepare("INSERT INTO domain_ssl_settings (domainid, ssl_cert_file, ssl_key_file, ssl_ca_file, ssl_cert_chainfile, ssl_fullchain_file, validtodate)
	VALUES (:id, :c, :k, :ca, :ch, :f, '2099-01-01')");
foreach ([1 => ['example.de', 'mail.example.de', 'alias.de', 'mail.alias.de'], 3 => ['off.de', 'mail.off.de'], 4 => ['cust-off.de', 'mail.cust-off.de'], 5 => ['nomail.de', 'mail.nomail.de']] as $id => $names) {
	$r = TestCertificates::sslRow($id, TestCertificates::leaf($names));
	Database::pexecute($ssl, ['id' => $id, 'c' => $r['ssl_cert_file'], 'k' => $r['ssl_key_file'], 'ca' => $r['ssl_ca_file'], 'ch' => $r['ssl_cert_chainfile'], 'f' => $r['ssl_fullchain_file']]);
}
$src = new DatabaseDataSource();
$certs = $src->getCertificates();
check(count($src->getDomains()) === 5 && count($certs) === 4 && !empty($certs[1]['validtodate']), 'DatabaseDataSource queries work on the official schema');
$entries = (new MailHostResolver(new MailSniConfig(['mail.sni_hostnames' => 'mail'])))->resolve($src->getDomains(), $certs);
check(array_keys($entries) === ['mail.alias.de', 'mail.example.de'], 'resolved: ' . implode(', ', array_keys($entries)));

exit($fails);
