<?php

// lightweight bootstrap for the mail-SNI tests: no database required
require dirname(__DIR__, 2) . '/vendor/autoload.php';
require_once __DIR__ . '/Support/TestCertificates.php';
require_once __DIR__ . '/Support/FakeRunner.php';
require_once __DIR__ . '/Support/MemoryLogger.php';
require_once __DIR__ . '/Support/ArrayDataSource.php';
require_once __DIR__ . '/Support/FakeHostnameChecker.php';
