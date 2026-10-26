<?php
/**
 * runs the mail-SNI sync against the REAL postfix/dovecot of the test container
 * usage: php integration.php <state.json>   (state: domains + certificate files, written by run.sh)
 */
require '/src/vendor/autoload.php';
require '/src/tests/MailSni/Support/ArrayDataSource.php';

use Froxlor\Cron\Mail\Sni\MailSni;
use Froxlor\Cron\Mail\Sni\MailSniConfig;
use Froxlor\Cron\Mail\Sni\ProcessCommandRunner;
use Froxlor\Cron\Mail\Sni\SniLogger;
use Froxlor\Tests\MailSni\ArrayDataSource;

$state = json_decode(file_get_contents($argv[1]), true);
$source = new ArrayDataSource();
foreach ($state['domains'] as $id => $d) {
	$source->addDomain((int)$id, $d['domain'], $d['extra'] ?? []);
	if (!empty($d['cert'])) {
		$source->certificates[(int)$id] = [
			'ssl_cert_file' => file_get_contents($d['cert']),
			'ssl_key_file' => file_get_contents($d['key']),
			'ssl_ca_file' => file_get_contents($d['chain']),
			'ssl_cert_chainfile' => file_get_contents($d['chain']),
			'ssl_fullchain_file' => file_get_contents($d['cert']) . file_get_contents($d['chain']),
		];
	}
}
$config = new MailSniConfig([
	'mail.sni_enabled' => $state['enabled'] ?? '1',
	'mail.sni_hostnames' => 'mail',
	'system.mtaserver' => 'postfix',
	'system.mdaserver' => 'dovecot',
	'system.hostname' => 'mx.test.local',
	'system.customer_ssl_path' => '/etc/ssl/froxlor-custom/',
	'system.mta_reload_command' => 'postfix reload',
	'system.mda_reload_command' => 'doveadm reload',
]);
$logger = new class implements SniLogger {
	public function log(int $level, string $message): void
	{
		if ($level <= LOG_INFO) {
			echo "  [log $level] $message\n";
		}
	}
};
$report = (new MailSni($config, $source, new ProcessCommandRunner(), $logger))->sync();
foreach ($report['results'] as $r) {
	echo "  => {$r->service}: {$r->status}\n";
}
echo 'RESULT ' . json_encode(array_map(function ($r) {
	return $r->status;
}, $report['results'])) . "\n";
