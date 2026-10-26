<?php

namespace Froxlor\Tests\MailSni;

use Froxlor\Cron\Mail\Sni\AcmeSanProvider;
use Froxlor\Cron\Mail\Sni\MailSniConfig;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Froxlor\Cron\Mail\Sni\AcmeSanProvider
 */
class AcmeSanProviderTest extends TestCase
{
	const OUR_IP = '192.0.2.10';

	private string $root;
	private ArrayDataSource $source;
	private FakeHostnameChecker $checker;
	private MemoryLogger $logger;
	private int $now;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/froxlor-mailsni-acme-' . bin2hex(random_bytes(4));
		$this->source = new ArrayDataSource();
		$this->checker = new FakeHostnameChecker();
		$this->logger = new MemoryLogger();
		$this->now = 1800000000;
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->root));
	}

	private function provider(array $settings = []): AcmeSanProvider
	{
		$config = new MailSniConfig(array_merge([
			'mail.sni_enabled' => '1',
			'mail.sni_acme' => '1',
			'mail.sni_cert_path' => $this->root . '/',
			'system.hostname' => 'srv.hoster.test',
		], $settings));
		return new AcmeSanProvider($config, $this->source, $this->checker, $this->logger, $this->root . '/acme-state.json', function () {
			return [self::OUR_IP];
		}, function () {
			return $this->now;
		});
	}

	private function local(string $host, ?string $base = null): void
	{
		$this->checker->a[$host] = [self::OUR_IP];
		$this->checker->reachable[$host] = true;
	}

	public function testMailHostnameIsAddedWhenValidatable()
	{
		$this->source->addDomain(1, 'example.de');
		$this->local('mail.example.de');
		$this->assertSame(['mail.example.de'], $this->provider()->additionalSans(1, ['example.de', 'www.example.de']));
	}

	public function testAliasDomainsGetMailHostnamesToo()
	{
		$this->source->addDomain(1, 'example.de');
		$this->source->addDomain(2, 'example.com', ['aliasdomain' => 1]);
		$this->local('mail.example.de');
		$this->local('mail.example.com');
		$this->assertSame(['mail.example.de', 'mail.example.com'], $this->provider()->additionalSans(1, ['example.de', 'example.com']));
	}

	public function testNoMailHostnameForExternalMailOrForeignDns()
	{
		// MX points to an external provider
		$this->source->addDomain(1, 'extmail.de');
		$this->local('mail.extmail.de');
		$this->checker->mx['extmail.de'] = ['mx01.provider.example'];
		$this->checker->a['mx01.provider.example'] = ['198.51.100.1'];
		// A record points elsewhere
		$this->source->addDomain(2, 'elsewhere.de');
		$this->checker->a['mail.elsewhere.de'] = ['198.51.100.7'];
		// no email domain at all
		$this->source->addDomain(3, 'web.de', ['isemaildomain' => 0]);
		$this->local('mail.web.de');
		// challenge not reachable
		$this->source->addDomain(4, 'nohttp.de');
		$this->checker->a['mail.nohttp.de'] = [self::OUR_IP];

		$p = $this->provider();
		$this->assertSame([], $p->additionalSans(1, ['extmail.de']));
		$this->assertTrue($this->logger->contains('handled by external servers'));
		$this->assertSame([], $p->additionalSans(2, ['elsewhere.de']));
		$this->assertTrue($this->logger->contains('does not resolve to an IP address of this system'));
		$this->assertSame([], $p->additionalSans(3, ['web.de']));
		$this->assertSame([], $p->additionalSans(4, ['nohttp.de']));
		$this->assertTrue($this->logger->contains('challenge is not reachable'));
	}

	public function testMxOnOwnServerIsAccepted()
	{
		$this->source->addDomain(1, 'example.de');
		$this->local('mail.example.de');
		$this->checker->mx['example.de'] = ['mx.hoster.test'];
		$this->checker->a['mx.hoster.test'] = [self::OUR_IP];
		$this->assertSame(['mail.example.de'], $this->provider()->additionalSans(1, ['example.de']));
	}

	public function testOwnFroxlorDomainIsNotDuplicated()
	{
		// mail.example.de exists as froxlor domain -> it gets its own certificate, no duplicate request
		$this->source->addDomain(1, 'example.de');
		$this->source->addDomain(2, 'mail.example.de', ['isemaildomain' => 0, 'parentdomainid' => 1]);
		$this->local('mail.example.de');
		$this->assertSame([], $this->provider()->additionalSans(1, ['example.de']));
		// already part of the request
		$this->assertSame([], $this->provider(['mail.sni_hostnames' => 'www'])->additionalSans(1, ['example.de', 'www.example.de']));
	}

	public function testFailedIssuanceBacksOffSoWebCertificateIsNotBlocked()
	{
		$this->source->addDomain(1, 'example.de');
		$this->local('mail.example.de');
		$p = $this->provider();
		$this->assertSame(['mail.example.de'], $p->additionalSans(1, ['example.de']));
		$p->reportIssueResult(['mail.example.de'], false);

		// retry 5 minutes later (new cron run, new instance): without mail hostname
		$this->now += 300;
		$this->assertSame([], $this->provider()->additionalSans(1, ['example.de']));
		$this->assertTrue($this->logger->contains('previous certificate request failed'));

		// after the backoff it is tried again
		$this->now += AcmeSanProvider::FAILURE_BACKOFF;
		$this->assertSame(['mail.example.de'], $this->provider()->additionalSans(1, ['example.de']));
	}

	public function testScheduleReissueForExistingCertificates()
	{
		// certificate without mail hostname -> needs re-issue
		$this->source->addDomain(1, 'old.de');
		$this->source->certificates[1] = TestCertificates::sslRow(1, TestCertificates::leaf(['old.de', 'www.old.de']));
		$this->local('mail.old.de');
		// already contains the mail hostname -> nothing to do
		$this->source->addDomain(2, 'done.de');
		$this->source->certificates[2] = TestCertificates::sslRow(2, TestCertificates::leaf(['done.de', 'mail.done.de']));
		$this->local('mail.done.de');
		// already waiting for (re-)issue
		$this->source->addDomain(3, 'pending.de');
		$this->source->certificates[3] = TestCertificates::sslRow(3, TestCertificates::leaf(['pending.de']), '');
		$this->local('mail.pending.de');
		// not managed by let's encrypt
		$this->source->addDomain(4, 'manual.de', ['letsencrypt' => 0]);
		$this->source->certificates[4] = TestCertificates::sslRow(4, TestCertificates::leaf(['manual.de']));
		$this->local('mail.manual.de');

		$marked = [];
		$result = $this->provider()->scheduleReissues(function ($id) use (&$marked) {
			$marked[] = $id;
		});
		$this->assertSame([1], $marked);
		$this->assertSame(['old.de'], $result);

		// checks are cached: no DNS lookups within RECHECK_INTERVAL
		$lookups = $this->checker->lookups;
		$this->provider()->scheduleReissues(function () {
		});
		$this->assertSame($lookups, $this->checker->lookups);
	}

	public function testScheduleRemovalOnlyAfterRepeatedFailures()
	{
		$this->source->addDomain(1, 'moved.de');
		$this->source->certificates[1] = TestCertificates::sslRow(1, TestCertificates::leaf(['moved.de', 'mail.moved.de']));
		// mail.moved.de now points elsewhere -> would break the renewal of the whole certificate
		$this->checker->a['mail.moved.de'] = ['198.51.100.9'];
		$marked = [];
		$mark = function ($id) use (&$marked) {
			$marked[] = $id;
		};
		$this->provider()->scheduleReissues($mark);
		$this->assertSame([], $marked, 'a single failed check must not trigger a re-issue');

		$this->now += AcmeSanProvider::RECHECK_INTERVAL + 1;
		$this->provider()->scheduleReissues($mark);
		$this->assertSame([1], $marked);
		$this->assertTrue($this->logger->contains('to remove mail.moved.de'));
	}

	public function testReissuesAreLimitedPerRun()
	{
		for ($i = 1; $i <= AcmeSanProvider::MAX_REISSUES_PER_RUN + 3; $i++) {
			$this->source->addDomain($i, 'd' . $i . '.de');
			$this->source->certificates[$i] = TestCertificates::sslRow($i, TestCertificates::leaf(['d' . $i . '.de']));
			$this->local('mail.d' . $i . '.de');
		}
		$marked = $this->provider()->scheduleReissues(function () {
		});
		$this->assertCount(AcmeSanProvider::MAX_REISSUES_PER_RUN, $marked);
	}

	public function testDisabledAcmePartIsNotCreated()
	{
		$config = new MailSniConfig(['mail.sni_enabled' => '1', 'mail.sni_acme' => '0']);
		$this->assertFalse($config->isAcmeEnabled());
		$config = new MailSniConfig(['mail.sni_enabled' => '0', 'mail.sni_acme' => '1']);
		$this->assertFalse($config->isAcmeEnabled());
	}
}
