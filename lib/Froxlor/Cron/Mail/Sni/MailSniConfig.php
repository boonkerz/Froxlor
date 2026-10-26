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

use Froxlor\Settings;

/**
 * Settings of the mail-SNI feature.
 *
 * The settings are NOT introduced via a database-version update step on purpose:
 * froxlor's update chain is strictly linear and any foreign DBVERSION breaks
 * future upstream updates. Instead, missing rows are added idempotently via
 * Settings::AddNew() (which only inserts if the setting does not yet exist),
 * so a later upstream update adding the same settings is a no-op.
 */
class MailSniConfig
{
	/**
	 * setting => default value
	 */
	const DEFAULTS = [
		// master switch
		'mail.sni_enabled' => '0',
		// comma separated list of hostname-prefixes, "@" means the domain itself
		'mail.sni_hostnames' => 'mail',
		// add the mail-hostnames to the let's encrypt certificate of the domain
		'mail.sni_acme' => '1',
		// own, root-only directory for the deployed key/fullchain files, state and backups
		'mail.sni_cert_path' => '/etc/ssl/froxlor-mail-sni/',
		'mail.sni_postfix_map' => '/etc/postfix/99-froxlor.map',
		'mail.sni_dovecot_conf' => '/etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf',
		// same names as used in froxlor PR #1423 to stay forward compatible
		'system.mda_reload_command' => 'systemctl reload dovecot',
		'system.mta_reload_command' => 'systemctl reload postfix',
	];

	/**
	 * settings which were used by an old, unofficial fork (DBVERSION 202402190);
	 * they are reported by the diagnose-command but never used or removed.
	 */
	const LEGACY_SETTINGS = [
		'system.mail_sni_enabled',
		'system.mda_conf_dir',
		'system.mta_conf_dir',
	];

	private array $values;

	public function __construct(array $values = [])
	{
		$this->values = array_merge(self::DEFAULTS, $values);
	}

	/**
	 * read current values from froxlor's settings (falls back to defaults if not yet present)
	 */
	public static function fromSettings(): self
	{
		$values = [];
		foreach (array_keys(self::DEFAULTS) as $setting) {
			$value = Settings::Get($setting);
			if ($value !== null) {
				$values[$setting] = (string)$value;
			}
		}
		$values['system.mdaserver'] = (string)Settings::Get('system.mdaserver');
		$values['system.mtaserver'] = (string)Settings::Get('system.mtaserver');
		$values['system.hostname'] = (string)Settings::Get('system.hostname');
		$values['system.customer_ssl_path'] = (string)Settings::Get('system.customer_ssl_path');
		$values['system.le_renew_services'] = (string)Settings::Get('system.le_renew_services');
		return new self($values);
	}

	/**
	 * idempotently add missing settings - never changes existing values,
	 * never touches panel.db_version
	 *
	 * @return string[] list of settings that have been added
	 */
	public static function ensureSettings(): array
	{
		$added = [];
		foreach (self::DEFAULTS as $setting => $default) {
			if (Settings::Get($setting) === null && Settings::AddNew($setting, $default)) {
				$added[] = $setting;
			}
		}
		return $added;
	}

	public function get(string $setting): string
	{
		return (string)($this->values[$setting] ?? '');
	}

	public function isEnabled(): bool
	{
		return $this->get('mail.sni_enabled') == '1';
	}

	public function isAcmeEnabled(): bool
	{
		return $this->isEnabled() && $this->get('mail.sni_acme') == '1';
	}

	public function usePostfix(): bool
	{
		return $this->get('system.mtaserver') === 'postfix';
	}

	public function useDovecot(): bool
	{
		return $this->get('system.mdaserver') === 'dovecot';
	}

	/**
	 * @return string[] e.g. ['mail'] or ['@', 'mail', 'imap']
	 */
	public function hostnamePrefixes(): array
	{
		$prefixes = [];
		foreach (explode(',', strtolower($this->get('mail.sni_hostnames'))) as $prefix) {
			$prefix = trim($prefix, " \t\n\r\0\x0B.");
			if ($prefix === '@' || preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/', $prefix)) {
				$prefixes[] = $prefix;
			}
		}
		return array_values(array_unique($prefixes));
	}

	/**
	 * mail hostnames for a given domain, e.g. mail.example.com
	 *
	 * @return string[]
	 */
	public function hostnamesFor(string $domain): array
	{
		$domain = strtolower(rtrim($domain, '.'));
		$result = [];
		foreach ($this->hostnamePrefixes() as $prefix) {
			$result[] = $prefix === '@' ? $domain : $prefix . '.' . $domain;
		}
		return $result;
	}

	public function certPath(): string
	{
		return rtrim($this->get('mail.sni_cert_path'), '/') . '/';
	}

	public function postfixMap(): string
	{
		return $this->get('mail.sni_postfix_map');
	}

	public function dovecotConf(): string
	{
		return $this->get('mail.sni_dovecot_conf');
	}

	/**
	 * hostnames that are served by the default certificate and must never get an SNI entry
	 *
	 * @return string[]
	 */
	public function excludedHostnames(): array
	{
		$hostname = strtolower(trim($this->get('system.hostname')));
		return $hostname === '' ? [] : [$hostname];
	}

	/**
	 * sanity check of the configured paths
	 *
	 * @return string[] list of problems (empty if fine)
	 */
	public function validatePaths(): array
	{
		$errors = [];
		$certPath = $this->certPath();
		if ($certPath === '/' || substr($certPath, 0, 1) !== '/' || strpos($certPath, '..') !== false) {
			$errors[] = 'mail.sni_cert_path must be an absolute, dedicated directory';
		}
		$customerSsl = rtrim($this->get('system.customer_ssl_path'), '/') . '/';
		if ($customerSsl !== '/' && $certPath === $customerSsl) {
			$errors[] = 'mail.sni_cert_path must not be the same directory as system.customer_ssl_path';
		}
		foreach (['mail.sni_postfix_map' => $this->postfixMap(), 'mail.sni_dovecot_conf' => $this->dovecotConf()] as $name => $file) {
			if ($file === '' || substr($file, 0, 1) !== '/' || substr($file, -1) === '/' || strpos($file, '..') !== false) {
				$errors[] = $name . ' must be an absolute filename';
			}
		}
		foreach (['mail.sni_cert_path' => $certPath, 'mail.sni_postfix_map' => $this->postfixMap(), 'mail.sni_dovecot_conf' => $this->dovecotConf()] as $name => $path) {
			// the paths end up unquoted in postfix/dovecot configuration files
			if (!preg_match('#^[A-Za-z0-9._/-]*$#', $path)) {
				$errors[] = $name . ' contains unsupported characters';
			}
		}
		if ($this->postfixMap() !== '' && $this->postfixMap() === $this->dovecotConf()) {
			$errors[] = 'mail.sni_postfix_map and mail.sni_dovecot_conf must differ';
		}
		return $errors;
	}
}
