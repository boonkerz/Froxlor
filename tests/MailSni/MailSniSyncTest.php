<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\MailSni;
use Froxlor\Cron\Mail\Sni\MailSniConfig;
use Froxlor\Cron\Mail\Sni\ServiceResult;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\Mail\Sni\MailSni
 * @covers \Froxlor\Cron\Mail\Sni\PostfixSni
 * @covers \Froxlor\Cron\Mail\Sni\DovecotSni
 * @covers \Froxlor\Cron\Mail\Sni\CertificateStore
 * @covers \Froxlor\Cron\Mail\Sni\MailHostResolver
 * @covers \Froxlor\Cron\Mail\Sni\FileTransaction
 */
class MailSniSyncTest extends TestCase
{
	private string $root;
	private ArrayDataSource $source;
	private FakeRunner $runner;
	private MemoryLogger $logger;
	private array $settings;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/froxlor-mailsni-' . bin2hex(random_bytes(4));
		mkdir($this->root . '/etc/postfix', 0755, true);
		mkdir($this->root . '/etc/dovecot/conf.d', 0755, true);
		file_put_contents($this->root . '/etc/postfix/main.cf', "smtpd_tls_chain_files = /etc/ssl/default.pem\n");
		$this->settings = [
			'mail.sni_enabled' => '1',
			'mail.sni_hostnames' => 'mail',
			'mail.sni_cert_path' => $this->root . '/ssl/',
			'mail.sni_postfix_map' => $this->root . '/etc/postfix/99-froxlor.map',
			'mail.sni_dovecot_conf' => $this->root . '/etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf',
			'system.mtaserver' => 'postfix',
			'system.mdaserver' => 'dovecot',
			'system.hostname' => 'srv.hoster.test',
			'system.customer_ssl_path' => $this->root . '/froxlor-custom/',
		];
		$this->source = new ArrayDataSource();
		$this->runner = new FakeRunner();
		$this->runner->sniMapsParam = 'hash:' . $this->settings['mail.sni_postfix_map'];
		$this->runner->doveconfFile = $this->settings['mail.sni_dovecot_conf'];
		$this->runner->mainCf = $this->root . '/etc/postfix/main.cf';
		$this->logger = new MemoryLogger();
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->root));
	}

	private function sync(array $settings = [], bool $dryRun = false, ?int $now = null): array
	{
		$config = new MailSniConfig(array_merge($this->settings, $settings));
		$sni = new MailSni($config, $this->source, $this->runner, $this->logger, $now === null ? null : function () use ($now) {
			return $now;
		});
		return $sni->sync($dryRun);
	}

	private function map(): string
	{
		return (string)@file_get_contents($this->settings['mail.sni_postfix_map']);
	}

	private function dovecot(): string
	{
		return (string)@file_get_contents($this->settings['mail.sni_dovecot_conf']);
	}

	private function addLeDomain(int $id, string $domain, array $names = null, array $extra = []): array
	{
		$leaf = TestCertificates::leaf($names ?? [$domain, 'www.' . $domain, 'mail.' . $domain]);
		$this->source->addDomain($id, $domain, $extra);
		$this->source->certificates[$id] = TestCertificates::sslRow($id, $leaf);
		return $leaf;
	}

	/**
	 * 1. new mail domain with valid certificate
	 */
	public function testNewMailDomainWithValidCertificate()
	{
		$leaf = $this->addLeDomain(1, 'example.de');
		$report = $this->sync();

		$this->assertSame(['mail.example.de'], array_keys($report['entries']));
		$certPath = $this->settings['mail.sni_cert_path'];
		$this->assertStringContainsString('mail.example.de ' . $certPath . 'mail.example.de.key ' . $certPath . 'mail.example.de_fullchain.pem', $this->map());
		$this->assertStringContainsString("local_name mail.example.de {\n  ssl_cert = <" . $certPath . "mail.example.de_fullchain.pem\n  ssl_key = <" . $certPath . "mail.example.de.key\n}", $this->dovecot());

		// deployed files: validated pair, key protected
		$this->assertSame(trim($leaf['key']), trim(file_get_contents($certPath . 'mail.example.de.key')));
		$this->assertSame(0600, fileperms($certPath . 'mail.example.de.key') & 0777);
		$this->assertSame(0700, fileperms($certPath) & 0777);
		$this->assertSame(0600, fileperms($this->settings['mail.sni_postfix_map'] . '.db') & 0777);
		$this->assertStringStartsWith(trim($leaf['cert']), file_get_contents($certPath . 'mail.example.de_fullchain.pem'));

		// validated + reloaded exactly once each, default certificate untouched
		$this->assertContains('postfix check', $this->runner->calls);
		$this->assertContains('doveconf -n', $this->runner->calls);
		$this->assertSame(['systemctl reload postfix', 'systemctl reload dovecot'], $this->runner->reloads());
		$this->assertSame(ServiceResult::UPDATED, $report['results']['postfix']->status);
		$this->assertStringContainsString('smtpd_tls_chain_files = /etc/ssl/default.pem', file_get_contents($this->runner->mainCf));
		// private keys never end up in the log
		$this->assertStringNotContainsString('PRIVATE KEY', $this->logger->all());
	}

	/**
	 * 2. new mail domain without (matching) certificate
	 */
	public function testNewMailDomainWithoutCertificate()
	{
		$this->source->addDomain(1, 'nocert.de');
		// certificate exists but does not cover mail.<domain> (e.g. dns check failed for it)
		$this->addLeDomain(2, 'web-only.de', ['web-only.de', 'www.web-only.de']);
		$report = $this->sync();

		$this->assertEmpty($report['entries']);
		$this->assertSame('no certificate available', $report['skipped']['mail.nocert.de']);
		$this->assertStringContainsString('does not cover mail.web-only.de', $report['skipped']['mail.web-only.de']);
		$this->assertStringNotContainsString('local_name', $this->dovecot());
		$this->assertFileDoesNotExist($this->settings['mail.sni_cert_path'] . 'mail.nocert.de.key');
	}

	/**
	 * 3. renewal: same paths, new certificate -> exactly one rewrite + reload
	 */
	public function testRenewalOfExistingCertificate()
	{
		$this->addLeDomain(1, 'example.de');
		$this->sync();
		$oldMap = $this->map();
		$this->runner->configured = [];

		$renewed = TestCertificates::leaf(['example.de', 'www.example.de', 'mail.example.de']);
		$this->source->certificates[1] = TestCertificates::sslRow(1, $renewed);
		$report = $this->sync();

		$this->assertNotSame($oldMap, $this->map(), 'fingerprint comment must change on renewal');
		$this->assertSame(trim($renewed['key']), trim(file_get_contents($this->settings['mail.sni_cert_path'] . 'mail.example.de.key')));
		$this->assertSame(['systemctl reload postfix', 'systemctl reload dovecot'], $this->runner->reloads());
		$this->assertSame(ServiceResult::UPDATED, $report['results']['dovecot']->status);
		// postfix table embeds the new key (postmap -F)
		$db = json_decode(file_get_contents($this->settings['mail.sni_postfix_map'] . '.db'), true);
		$this->assertStringContainsString(trim($renewed['cert']), $db['mail.example.de']);
	}

	/**
	 * 4. certificate and key do not match / unparsable / expired
	 */
	public function testInvalidCertificateKeyPair()
	{
		$a = $this->addLeDomain(1, 'good.de');
		$b = $this->addLeDomain(2, 'broken.de');
		$other = TestCertificates::leaf(['other.de']);
		$this->source->certificates[2]['ssl_key_file'] = $other['key'];
		$this->addLeDomain(3, 'garbage.de');
		$this->source->certificates[3]['ssl_cert_file'] = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----";
		$this->source->certificates[3]['ssl_fullchain_file'] = '';

		$report = $this->sync();
		$this->assertSame(['mail.good.de'], array_keys($report['entries']));
		$this->assertStringContainsString('does not match its private key', $report['skipped']['mail.broken.de']);
		$this->assertStringContainsString('cannot be parsed', $report['skipped']['mail.garbage.de']);
		$this->assertStringNotContainsString('broken.de', $this->dovecot() . $this->map());

		// expired certificates are skipped as well
		$report = $this->sync([], false, time() + 200 * 86400);
		$this->assertEmpty($report['entries']);
		$this->assertStringContainsString('expired', $report['skipped']['mail.good.de']);
	}

	/**
	 * 5. removal of a mail domain (deleted, deactivated or email disabled)
	 */
	public function testRemovalOfMailDomain()
	{
		$this->addLeDomain(1, 'stay.de');
		$this->addLeDomain(2, 'gone.de');
		$this->addLeDomain(3, 'nomail.de');
		$this->sync();
		$certPath = $this->settings['mail.sni_cert_path'];
		$this->assertFileExists($certPath . 'mail.gone.de.key');

		unset($this->source->domains[2], $this->source->certificates[2]);
		$this->source->domains[3]['isemaildomain'] = 0;
		$this->runner->configured = [];
		$report = $this->sync();

		$this->assertSame(['mail.stay.de'], array_keys($report['entries']));
		$this->assertStringNotContainsString('gone.de', $this->dovecot() . $this->map());
		$this->assertStringNotContainsString('nomail.de', $this->dovecot() . $this->map());
		$this->assertFileDoesNotExist($certPath . 'mail.gone.de.key');
		$this->assertFileDoesNotExist($certPath . 'mail.gone.de_fullchain.pem');
		$this->assertSame(['systemctl reload postfix', 'systemctl reload dovecot'], $this->runner->reloads());
	}

	/**
	 * 6. several domains with different certificates (own subdomain cert, SAN, alias, wildcard)
	 */
	public function testMultipleDomainsWithDifferentCertificates()
	{
		// a) mail.a.de is a froxlor domain of its own with its own certificate (old fork setup)
		$this->addLeDomain(1, 'a.de', ['a.de', 'www.a.de']);
		$own = $this->addLeDomain(2, 'mail.a.de', ['mail.a.de'], ['isemaildomain' => 0, 'parentdomainid' => 1]);
		// b) mail.b.de as SAN in the certificate of b.de
		$this->addLeDomain(3, 'b.de');
		// c) alias domain c.de -> b.de, certificate of b.de contains mail.c.de
		$this->source->certificates[3] = TestCertificates::sslRow(3, $bLeaf = TestCertificates::leaf(['b.de', 'mail.b.de', 'c.de', 'mail.c.de']));
		$this->source->addDomain(4, 'c.de', ['aliasdomain' => 3]);
		// d) subdomain shop.d.de covered by wildcard certificate of d.de (manually uploaded, no fullchain)
		$wild = TestCertificates::leaf(['d.de', '*.d.de']);
		$this->source->addDomain(5, 'd.de', ['isemaildomain' => 0, 'letsencrypt' => 0]);
		$this->source->certificates[5] = TestCertificates::sslRow(5, $wild);
		$this->source->certificates[5]['ssl_fullchain_file'] = '';
		$this->source->addDomain(6, 'shop.d.de', ['parentdomainid' => 5, 'letsencrypt' => 0]);

		$report = $this->sync(['mail.sni_hostnames' => 'mail,@']);
		$entries = $report['entries'];
		$this->assertSame(2, $entries['mail.a.de']->certDomainId);
		$this->assertSame(3, $entries['mail.b.de']->certDomainId);
		$this->assertSame(3, $entries['mail.c.de']->certDomainId);
		// a wildcard only covers one label: shop.d.de yes, mail.shop.d.de no
		$this->assertSame(5, $entries['shop.d.de']->certDomainId);
		$this->assertStringContainsString('does not cover mail.shop.d.de', $report['skipped']['mail.shop.d.de']);
		// "@" = the domain itself, served by its own certificate
		$this->assertSame(1, $entries['a.de']->certDomainId);
		$this->assertSame(1, substr_count($this->dovecot(), 'local_name mail.a.de {'), 'no duplicate local_name blocks');
		$this->assertSame(trim($own['key']), trim(file_get_contents($this->settings['mail.sni_cert_path'] . 'mail.a.de.key')));
		// fullchain of manually uploaded certificate = cert + chain
		$this->assertSame(2, substr_count(file_get_contents($this->settings['mail.sni_cert_path'] . 'shop.d.de_fullchain.pem'), 'BEGIN CERTIFICATE'));
	}

	/**
	 * 7. feature disabled: generated config is emptied, foreign config is never touched
	 */
	public function testDisabledFeature()
	{
		// foreign (hand-made / old fork) files are left alone while disabled
		file_put_contents($this->settings['mail.sni_dovecot_conf'], "local_name legacy.de {\n}\n");
		$report = $this->sync(['mail.sni_enabled' => '0']);
		$this->assertEmpty($report['results']);
		$this->assertSame("local_name legacy.de {\n}\n", $this->dovecot());
		$this->assertEmpty($this->runner->calls);

		// enabled -> generated (foreign file is backed up before it is replaced)
		$this->addLeDomain(1, 'example.de');
		$this->sync();
		$this->assertStringContainsString('local_name mail.example.de', $this->dovecot());
		$backups = glob($this->settings['mail.sni_cert_path'] . 'backups/*/*99-froxlor-vhost.ssl.conf');
		$this->assertCount(1, $backups);
		$this->assertSame("local_name legacy.de {\n}\n", file_get_contents($backups[0]));

		// disabled again -> entries removed, files stay valid (empty table), main.cf untouched
		$this->runner->configured = [];
		$this->sync(['mail.sni_enabled' => '0']);
		$this->assertStringNotContainsString('local_name', $this->dovecot());
		$this->assertStringNotContainsString('mail.example.de /', $this->map());
		$this->assertFileExists($this->settings['mail.sni_postfix_map'] . '.db');
		$this->assertFileDoesNotExist($this->settings['mail.sni_cert_path'] . 'mail.example.de.key');
		$this->assertSame(['systemctl reload postfix', 'systemctl reload dovecot'], $this->runner->reloads());

		// and nothing happens any more afterwards
		$this->runner->calls = [];
		$this->runner->configured = [];
		$this->sync(['mail.sni_enabled' => '0']);
		$this->assertSame([], $this->runner->configured);
	}

	/**
	 * 8. repeated run without changes: idempotent, no write, no reload
	 */
	public function testRepeatedRunWithoutChanges()
	{
		$this->addLeDomain(1, 'example.de');
		$this->addLeDomain(2, 'example.com');
		$this->sync();
		$map = $this->map();
		$mtimeKey = filemtime($this->settings['mail.sni_cert_path'] . 'mail.example.de.key');
		$this->runner->configured = [];
		$this->runner->calls = [];

		$report = $this->sync();
		$this->assertSame(ServiceResult::UNCHANGED, $report['results']['postfix']->status);
		$this->assertSame(ServiceResult::UNCHANGED, $report['results']['dovecot']->status);
		$this->assertSame([], $this->runner->configured, 'no reload without changes');
		$this->assertNotContains('postfix check', $this->runner->calls);
		$this->assertSame($map, $this->map());
		$this->assertSame($mtimeKey, filemtime($this->settings['mail.sni_cert_path'] . 'mail.example.de.key'));
		$this->assertEmpty(glob($this->settings['mail.sni_cert_path'] . 'backups/*', GLOB_ONLYDIR) ?: [], 'no backups without changes');
	}

	/**
	 * 9a. "postfix check" fails -> previous table restored, no reload; dovecot handled independently
	 */
	public function testPostfixCheckFailureRollsBack()
	{
		$this->addLeDomain(1, 'example.de');
		$this->sync();
		$goodMap = $this->map();
		$goodDb = file_get_contents($this->settings['mail.sni_postfix_map'] . '.db');

		$this->addLeDomain(2, 'new.de');
		$this->runner->postfixCheckCode = 1;
		$this->runner->configured = [];
		$report = $this->sync();

		$this->assertSame(ServiceResult::FAILED, $report['results']['postfix']->status);
		$this->assertSame($goodMap, $this->map());
		$this->assertSame($goodDb, file_get_contents($this->settings['mail.sni_postfix_map'] . '.db'));
		$this->assertSame(['systemctl reload dovecot'], $this->runner->reloads());
		$this->assertTrue($this->logger->contains('postfix check', LOG_ERR));
		$this->assertEmpty(glob(dirname($this->settings['mail.sni_postfix_map']) . '/.*froxlor-tmp*'), 'no temp files left');

		// next run retries and succeeds once the problem is fixed
		$this->runner->postfixCheckCode = 0;
		$report = $this->sync();
		$this->assertSame(ServiceResult::UPDATED, $report['results']['postfix']->status);
		$this->assertStringContainsString('mail.new.de', $this->map());
	}

	/**
	 * 9b. "doveconf -n" fails -> previous file restored, no reload, stale cert files kept
	 */
	public function testDoveconfFailureRollsBack()
	{
		$this->addLeDomain(1, 'example.de');
		$this->addLeDomain(2, 'old.de');
		$this->sync();
		$good = $this->dovecot();

		unset($this->source->domains[2], $this->source->certificates[2]);
		$this->runner->doveconfCode = 1;
		$this->runner->configured = [];
		$report = $this->sync();

		$this->assertSame(ServiceResult::FAILED, $report['results']['dovecot']->status);
		$this->assertSame($good, $this->dovecot());
		$this->assertNotContains('systemctl reload dovecot', $this->runner->reloads());
		// still referenced by the restored dovecot config -> must not be deleted
		$this->assertFileExists($this->settings['mail.sni_cert_path'] . 'mail.old.de.key');
	}

	/**
	 * 9c. postmap fails / old postfix / dry-run / invalid configuration
	 */
	public function testGenerationErrors()
	{
		$this->addLeDomain(1, 'example.de');
		$this->runner->postmapCode = 1;
		$report = $this->sync();
		$this->assertSame(ServiceResult::FAILED, $report['results']['postfix']->status);
		$this->assertFileDoesNotExist($this->settings['mail.sni_postfix_map']);
		$this->assertNotContains('systemctl reload postfix', $this->runner->reloads());

		$this->runner->postmapCode = 0;
		$this->runner->postfixVersion = '3.3.0';
		$report = $this->sync();
		$this->assertSame(ServiceResult::FAILED, $report['results']['postfix']->status);
		$this->assertStringContainsString('3.4', $report['results']['postfix']->message);

		$report = $this->sync(['mail.sni_cert_path' => $this->settings['system.customer_ssl_path']]);
		$this->assertNotEmpty($report['errors']);
		$this->assertEmpty($report['results']);
	}

	public function testDryRunChangesNothing()
	{
		$this->addLeDomain(1, 'example.de');
		$report = $this->sync([], true);
		$this->assertSame(ServiceResult::DRYRUN, $report['results']['postfix']->status);
		$this->assertSame(ServiceResult::DRYRUN, $report['results']['dovecot']->status);
		$this->assertFileDoesNotExist($this->settings['mail.sni_postfix_map']);
		$this->assertFileDoesNotExist($this->settings['mail.sni_dovecot_conf']);
		$this->assertDirectoryDoesNotExist($this->settings['mail.sni_cert_path']);
		$this->assertSame([], $this->runner->configured);
	}

	public function testPostfixParameterHandling()
	{
		$this->addLeDomain(1, 'example.de');
		// not set yet -> set (after backup of main.cf)
		$this->runner->sniMapsParam = '';
		$this->sync();
		$this->assertSame('hash:' . $this->settings['mail.sni_postfix_map'], $this->runner->sniMapsParam);
		$this->assertCount(1, glob($this->settings['mail.sni_cert_path'] . 'backups/*/*main.cf'));

		// foreign table configured -> never changed, no reload
		$this->runner->sniMapsParam = 'hash:/etc/postfix/my-own-sni';
		$this->addLeDomain(2, 'new.de');
		$this->runner->configured = [];
		$report = $this->sync();
		$this->assertSame('hash:/etc/postfix/my-own-sni', $this->runner->sniMapsParam);
		$this->assertStringContainsString('NOT active', $report['results']['postfix']->message);
		$this->assertSame(['systemctl reload dovecot'], $this->runner->reloads());
	}

	public function testDovecot24Syntax()
	{
		$this->runner->dovecotVersion = '2.4.1-4 (7d8c0e5759)';
		$this->addLeDomain(1, 'example.de');
		$this->sync();
		$certPath = $this->settings['mail.sni_cert_path'];
		$this->assertStringContainsString("local_name mail.example.de {\n  ssl_server_cert_file = " . $certPath . "mail.example.de_fullchain.pem\n  ssl_server_key_file = " . $certPath . "mail.example.de.key\n}", $this->dovecot());
	}

	public function testSystemHostnameAndDeactivatedDomainsAreSkipped()
	{
		$this->addLeDomain(1, 'hoster.test', ['hoster.test', 'srv.hoster.test'], []);
		$this->addLeDomain(2, 'off.de', null, ['deactivated' => 1]);
		$this->addLeDomain(3, 'custoff.de', null, ['customer_deactivated' => 1]);
		$report = $this->sync(['mail.sni_hostnames' => 'srv,mail']);
		$this->assertArrayNotHasKey('srv.hoster.test', $report['entries']);
		$this->assertStringContainsString('system hostname', $report['skipped']['srv.hoster.test']);
		$this->assertStringNotContainsString('off.de', $this->dovecot());
	}
}
