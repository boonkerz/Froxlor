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

/**
 * result of applying the configuration of one service
 */
class ServiceResult
{
	const UNCHANGED = 'unchanged';
	const UPDATED = 'updated';
	const SKIPPED = 'skipped';
	const FAILED = 'failed';
	const DRYRUN = 'dry-run';

	public string $service;
	public string $status;
	public string $message;
	public bool $reloadRequired;

	public function __construct(string $service, string $status, string $message = '', bool $reloadRequired = false)
	{
		$this->service = $service;
		$this->status = $status;
		$this->message = $message;
		$this->reloadRequired = $reloadRequired;
	}

	public function isOk(): bool
	{
		return $this->status !== self::FAILED;
	}
}
