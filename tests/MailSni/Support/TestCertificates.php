<?php

namespace Froxlor\Tests\MailSni;

/**
 * creates throw-away CA/leaf certificates for the tests
 */
class TestCertificates
{
	private static $ca = null;

	public static function ca(): array
	{
		if (self::$ca === null) {
			$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
			$csr = openssl_csr_new(['commonName' => 'froxlor test CA'], $key, ['digest_alg' => 'sha256']);
			$cert = openssl_csr_sign($csr, null, $key, 3650, ['digest_alg' => 'sha256'], random_int(1, PHP_INT_MAX));
			openssl_x509_export($cert, $certPem);
			openssl_pkey_export($key, $keyPem);
			self::$ca = ['cert' => $certPem, 'key' => $keyPem];
		}
		return self::$ca;
	}

	/**
	 * @return array{cert:string,key:string,chain:string,fullchain:string}
	 */
	public static function leaf(array $names, int $days = 90): array
	{
		$ca = self::ca();
		$conf = tempnam(sys_get_temp_dir(), 'frxsni');
		$san = implode(',', array_map(function ($n) {
			return 'DNS:' . $n;
		}, $names));
		file_put_contents($conf, "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=" . $san . "\nbasicConstraints=CA:FALSE\n");
		$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		$csr = openssl_csr_new(['commonName' => $names[0]], $key, ['digest_alg' => 'sha256', 'config' => $conf, 'req_extensions' => 'ext']);
		$cert = openssl_csr_sign($csr, $ca['cert'], $ca['key'], $days, ['digest_alg' => 'sha256', 'config' => $conf, 'x509_extensions' => 'ext'], random_int(1, PHP_INT_MAX));
		unlink($conf);
		openssl_x509_export($cert, $certPem);
		openssl_pkey_export($key, $keyPem);
		return ['cert' => $certPem, 'key' => $keyPem, 'chain' => $ca['cert'], 'fullchain' => $certPem . $ca['cert']];
	}

	/**
	 * a row like froxlor stores it in panel_domain_ssl_settings for let's encrypt certificates
	 */
	public static function sslRow(int $domainId, array $leaf, string $validto = '2099-01-01 00:00:00'): array
	{
		return [
			'domainid' => $domainId,
			'ssl_cert_file' => $leaf['cert'],
			'ssl_key_file' => $leaf['key'],
			'ssl_ca_file' => $leaf['chain'],
			'ssl_cert_chainfile' => $leaf['chain'],
			'ssl_fullchain_file' => $leaf['fullchain'],
			'validtodate' => $validto,
		];
	}
}
