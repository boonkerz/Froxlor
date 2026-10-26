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


namespace Froxlor\Cli;

use Froxlor\Cron\Mail\Sni\DatabaseDataSource;
use Froxlor\Cron\Mail\Sni\FroxlorSniLogger;
use Froxlor\Cron\Mail\Sni\MailSni;
use Froxlor\Cron\Mail\Sni\MailSniConfig;
use Froxlor\Cron\Mail\Sni\ProcessCommandRunner;
use Froxlor\Cron\Mail\Sni\ServiceResult;
use Froxlor\Cron\Mail\Sni\SniLogger;
use Froxlor\Froxlor;
use Froxlor\FroxlorLogger;
use Froxlor\Settings;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class MailSniCommand extends CliCommand
{

	protected function configure()
	{
		$this->setName('froxlor:mail-sni');
		$this->setDescription('Diagnose and synchronize the mail-SNI configuration (Postfix/Dovecot per-hostname certificates)');
		$this->addArgument('action', InputArgument::OPTIONAL, 'status (default): show what would be generated, nothing is changed | sync: apply now (same as the tasks-cron) | setup: add missing settings', 'status');
		$this->addOption('dry-run', null, InputOption::VALUE_NONE, 'with "sync": only show what would be changed');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$result = $this->validateRequirements($output);
		if ($result != self::SUCCESS) {
			return $result;
		}
		require_once Froxlor::getInstallDir() . '/lib/functions.php';

		$io = new SymfonyStyle($input, $output);
		$action = $input->getArgument('action');

		if (!in_array($action, ['status', 'sync', 'setup'])) {
			$io->error('Unknown action "' . $action . '"');
			return self::INVALID;
		}

		$added = MailSniConfig::ensureSettings();
		if (!empty($added)) {
			$io->note('Added missing settings: ' . implode(', ', $added) . ' (panel.db_version untouched)');
		}
		if ($action == 'setup') {
			$io->success('Settings are present.');
			return self::SUCCESS;
		}

		$dryRun = $action == 'status' || $input->getOption('dry-run');
		if (!$dryRun && function_exists('posix_geteuid') && posix_geteuid() != 0) {
			$io->error('"sync" has to be run as root');
			return self::FAILURE;
		}

		$config = MailSniConfig::fromSettings();
		$this->showSettings($io, $config);

		// in status-mode show what would be generated, even if the feature is still disabled
		$previewConfig = $config;
		if ($action == 'status' && !$config->isEnabled()) {
			$io->note('mail-SNI is disabled - showing what would be generated if it was enabled.');
			$previewConfig = new MailSniConfig(array_merge($this->configValues($config), ['mail.sni_enabled' => '1']));
		}

		$logger = new class(FroxlorLogger::getInstanceOf(), $dryRun, $output) implements SniLogger {
			private FroxlorSniLogger $inner;
			private OutputInterface $output;

			public function __construct(FroxlorLogger $logger, bool $quiet, OutputInterface $output)
			{
				// dry-runs are not written to the system log
				$this->inner = new FroxlorSniLogger($quiet ? null : $logger);
				$this->output = $output;
			}

			public function log(int $level, string $message): void
			{
				$this->inner->log($level, $message);
				if ($level <= LOG_WARNING || ($this->output->isVerbose() && $level < LOG_DEBUG) || $this->output->isVeryVerbose()) {
					$this->output->writeln(($level <= LOG_ERR ? '<error>' : '<comment>') . '[' . $level . '] ' . $message . '</>');
				}
			}
		};

		$sni = new MailSni($previewConfig, new DatabaseDataSource(), new ProcessCommandRunner(), $logger);
		$report = $sni->sync($dryRun);

		$rows = [];
		foreach ($report['entries'] as $entry) {
			$rows[] = [$entry->hostname, $entry->certDomain, gmdate('Y-m-d', $entry->certificate->validTo()), $entry->certificate->issuer(), substr($entry->certificate->fingerprint(), 0, 23) . '…'];
		}
		$io->section('SNI entries (' . count($rows) . ')');
		if (empty($rows)) {
			$io->text('none');
		} else {
			$io->table(['hostname', 'certificate of', 'valid until', 'issuer', 'sha256'], $rows);
		}
		if (!empty($report['skipped'])) {
			$io->section('Hostnames without SNI entry (' . count($report['skipped']) . ')');
			$rows = [];
			foreach ($report['skipped'] as $host => $reason) {
				$rows[] = [$host, $reason];
			}
			$io->table(['hostname', 'reason'], $rows);
		}

		$io->section('Services');
		$failed = !empty($report['errors']);
		foreach ($report['errors'] as $error) {
			$io->error($error);
		}
		foreach ($report['results'] as $res) {
			/** @var ServiceResult $res */
			$io->text(sprintf('<options=bold>%s</>: %s %s', $res->service, $res->status, trim($res->message)));
			$failed = $failed || !$res->isOk();
		}
		if (empty($report['results']) && empty($report['errors'])) {
			$io->text('nothing to do');
		}

		$this->showAcmeState($io, $config);

		return $failed ? self::FAILURE : self::SUCCESS;
	}

	private function showSettings(SymfonyStyle $io, MailSniConfig $config): void
	{
		$rows = [];
		foreach (array_keys(MailSniConfig::DEFAULTS) as $setting) {
			$rows[] = [$setting, $config->get($setting)];
		}
		$rows[] = ['system.mtaserver / system.mdaserver', $config->get('system.mtaserver') . ' / ' . $config->get('system.mdaserver')];
		$io->section('Settings');
		$io->table(['setting', 'value'], $rows);
		foreach (MailSniConfig::LEGACY_SETTINGS as $legacy) {
			if (Settings::Get($legacy) !== null) {
				$io->warning('Unused setting "' . $legacy . '" (from an unofficial fork) found in panel_settings - it is ignored and can be removed manually.');
			}
		}
		foreach (['system.mta_reload_command', 'system.mda_reload_command'] as $cmd) {
			if (preg_match('/\brestart\b/i', $config->get($cmd))) {
				$io->warning($cmd . ' = "' . $config->get($cmd) . '" restarts the service (drops connections) - consider "systemctl reload ..."');
			}
		}
	}

	private function showAcmeState(SymfonyStyle $io, MailSniConfig $config): void
	{
		$file = $config->certPath() . 'acme-state.json';
		if (!is_readable($file)) {
			return;
		}
		$state = json_decode((string)file_get_contents($file), true);
		if (!is_array($state) || empty($state)) {
			return;
		}
		$rows = [];
		ksort($state);
		foreach ($state as $host => $st) {
			$rows[] = [
				$host,
				!empty($st['ok']) ? 'ok' : 'no',
				empty($st['checked']) ? '-' : gmdate('Y-m-d H:i', $st['checked']),
				!empty($st['backoff_until']) && $st['backoff_until'] > time() ? gmdate('Y-m-d H:i', $st['backoff_until']) : '-',
				$st['reason'] ?? ''
			];
		}
		$io->section('Let\'s Encrypt checks of mail hostnames (UTC)');
		$io->table(['hostname', 'eligible', 'last check', 'backoff until', 'reason'], $rows);
	}

	private function configValues(MailSniConfig $config): array
	{
		$values = [];
		foreach (array_merge(array_keys(MailSniConfig::DEFAULTS), ['system.mdaserver', 'system.mtaserver', 'system.hostname', 'system.customer_ssl_path', 'system.le_renew_services']) as $key) {
			$values[$key] = $config->get($key);
		}
		return $values;
	}
}
