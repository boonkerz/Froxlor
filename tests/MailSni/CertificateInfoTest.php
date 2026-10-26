<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\CertificateInfo;
use Froxlor\Cron\Mail\Sni\MailSniConfig;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\Mail\Sni\CertificateInfo
 * @covers \Froxlor\Cron\Mail\Sni\MailSniConfig
 */
class CertificateInfoTest extends TestCase
{
	public function testSanMatching()
	{
		$leaf = TestCertificates::leaf(['example.de', 'mail.example.de', '*.example.com']);
		$cert = CertificateInfo::fromSslRow(TestCertificates::sslRow(1, $leaf));
		$this->assertTrue($cert->covers('mail.example.de'));
		$this->assertTrue($cert->covers('MAIL.example.de.'));
		$this->assertFalse($cert->covers('imap.example.de'));
		$this->assertTrue($cert->covers('mail.example.com'));
		$this->assertFalse($cert->covers('a.mail.example.com'));
		$this->assertFalse($cert->covers('example.com'));
		$this->assertTrue($cert->keyMatches());
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $cert->fingerprint());
	}

	public function testKeyIsNeverPrinted()
	{
		$leaf = TestCertificates::leaf(['example.de']);
		$cert = CertificateInfo::fromSslRow(TestCertificates::sslRow(1, $leaf));
		$this->assertStringNotContainsString('PRIVATE', (string)$cert);
		$this->assertStringNotContainsString('PRIVATE', print_r($cert, true));
	}

	public function testFullchainFromManualCertificate()
	{
		$leaf = TestCertificates::leaf(['example.de']);
		$row = TestCertificates::sslRow(1, $leaf);
		$row['ssl_fullchain_file'] = '';
		$row['ssl_cert_chainfile'] = '';
		$cert = CertificateInfo::fromSslRow($row);
		$this->assertSame(2, substr_count($cert->fullchainPem(), 'BEGIN CERTIFICATE'));
		// nginx-style: chain already appended to the certificate -> no duplicate
		$row['ssl_cert_file'] = $leaf['cert'] . $leaf['chain'];
		$cert = CertificateInfo::fromSslRow($row);
		$this->assertSame(2, substr_count($cert->fullchainPem(), 'BEGIN CERTIFICATE'));
	}

	public function testHostnamePrefixes()
	{
		$config = new MailSniConfig(['mail.sni_hostnames' => ' mail, @ ,imap,bad host,mail']);
		$this->assertSame(['mail', '@', 'imap'], $config->hostnamePrefixes());
		$this->assertSame(['mail.example.de', 'example.de', 'imap.example.de'], $config->hostnamesFor('Example.de'));
	}

	public function testPathValidation()
	{
		$this->assertSame([], (new MailSniConfig(['system.customer_ssl_path' => '/etc/ssl/froxlor-custom/']))->validatePaths());
		$this->assertNotEmpty((new MailSniConfig(['mail.sni_cert_path' => '/etc/ssl/froxlor-custom', 'system.customer_ssl_path' => '/etc/ssl/froxlor-custom/']))->validatePaths());
		$this->assertNotEmpty((new MailSniConfig(['mail.sni_cert_path' => '/']))->validatePaths());
		$this->assertNotEmpty((new MailSniConfig(['mail.sni_postfix_map' => '/etc/postfix/my map']))->validatePaths());
		$this->assertNotEmpty((new MailSniConfig(['mail.sni_dovecot_conf' => 'relative.conf']))->validatePaths());
	}

	public function testNoDatabaseVersionIsIntroduced()
	{
		// the feature must not compete with froxlor's linear update chain (see 202402190 incident)
		$root = dirname(__DIR__, 2);
		$this->assertSame('202608210', \Froxlor\Froxlor::DBVERSION);
		$this->assertStringNotContainsString('sni', strtolower(file_get_contents($root . '/install/updates/froxlor/update_2.3.inc.php')));
		$this->assertStringNotContainsString('202402190', file_get_contents($root . '/install/froxlor.sql.php'));
	}
}
