#!/bin/bash
# docker network create frxsni; docker run -d --name frxsni-db --network frxsni -e MARIADB_ROOT_PASSWORD=root mariadb:10.6
# docker run --rm --network frxsni -v $PWD:/src:ro froxlor-mailsni-test bash /src/tests/MailSni/integration/db-test.sh
set -e
rm -rf /work; cp -a /src /work; cd /work
cat > lib/userdata.inc.php <<'EOU'
<?php
$sql['user'] = 'root';
$sql['password'] = 'root';
$sql['host'] = 'frxsni-db';
$sql['db'] = 'froxlor';
$sql_root[0]['user'] = 'root';
$sql_root[0]['password'] = 'root';
$sql_root[0]['host'] = 'frxsni-db';
$sql_root[0]['caption'] = 'test';
$sql['debug'] = true;
EOU
php -r '
$pdo = new PDO("mysql:host=frxsni-db", "root", "root");
$pdo->exec("DROP DATABASE IF EXISTS froxlor; CREATE DATABASE froxlor CHARACTER SET utf8");
$pdo->exec("USE froxlor");
$pdo->exec(include "install/froxlor.sql.php");
$pdo->exec("INSERT INTO panel_admins (adminid, loginname, password, name, email, customers_see_all, caneditphpsettings, change_serversettings) VALUES (1, \"admin\", \"x\", \"admin\", \"a@b.c\", 1, 1, 1)");
echo "official 2.3.16 schema imported\n";'
php tests/MailSni/integration/db-test.php
echo "=== CLI: froxlor:mail-sni status ==="
php bin/froxlor-cli froxlor:mail-sni status --no-ansi | head -60
echo "=== tasks-cron hook (froxlor:cron tasks) ==="
php -r 'require "vendor/autoload.php"; require "lib/tables.inc.php";
\Froxlor\Settings::Set("mail.sni_enabled", "1"); \Froxlor\Settings::Set("mail.sni_hostnames", "mail");
\Froxlor\Settings::Set("system.mta_reload_command", "postfix reload"); \Froxlor\Settings::Set("system.mda_reload_command", "doveadm reload");
\Froxlor\Settings::Set("system.webserver", "none");'
postconf -e smtpd_tls_security_level=may >/dev/null; postfix start 2>/dev/null; dovecot 2>/dev/null || true
php bin/froxlor-cli froxlor:cron tasks --no-ansi 2>&1 | tail -5
echo "--- generated postfix map:"; grep -v '^#' /etc/postfix/99-froxlor.map | grep .
echo "--- tls_server_sni_maps = $(postconf -h tls_server_sni_maps)"
echo "--- generated dovecot conf:"; grep -A3 '^local_name' /etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf
echo "--- syslog entries:"; php -r '$p=new PDO("mysql:host=frxsni-db;dbname=froxlor","root","root"); foreach($p->query("SELECT text FROM panel_syslog WHERE text LIKE \"[mail-sni]%\" ORDER BY logid") as $r) echo $r[0],"\n";'
echo "--- second run (must be unchanged):"
php bin/froxlor-cli froxlor:cron tasks --no-ansi >/dev/null 2>&1
php -r '$p=new PDO("mysql:host=frxsni-db;dbname=froxlor","root","root"); foreach($p->query("SELECT text FROM panel_syslog WHERE text LIKE \"[mail-sni]%\" ORDER BY logid DESC LIMIT 3") as $r) echo $r[0],"\n";'
