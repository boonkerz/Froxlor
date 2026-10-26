#!/bin/bash
# Integration test: real Postfix 3.6.4 / Dovecot 2.3.16 (Ubuntu 22.04 container).
# docker build -t froxlor-mailsni-test tests/MailSni/integration
# docker run --rm -v $PWD:/src froxlor-mailsni-test bash /src/tests/MailSni/integration/run.sh
set -u
W=/tmp/sni; mkdir -p $W; cd $W
FAILS=0
ok()   { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS+1)); }

# --- certificates: test CA, default server cert, per-domain certs -----------------------
openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=Test CA" -keyout ca.key -out ca.pem -days 30 2>/dev/null
mkcert() { # name sans...
	local n=$1; shift; local san=$(printf "DNS:%s," "$@"); san=${san%,}
	openssl req -newkey rsa:2048 -nodes -subj "/CN=$1" -keyout $n.key -out $n.csr 2>/dev/null
	openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -out $n.pem \
		-extfile <(echo "subjectAltName=$san") 2>/dev/null
}
mkcert default mx.test.local
mkcert ex   example.de www.example.de mail.example.de
mkcert ex2  example.de www.example.de mail.example.de   # "renewed" certificate
mkcert org  example.org mail.example.org
mkcert bad  broken.de mail.broken.de
cp org.key bad.key                                      # key does not match certificate

# --- base configuration (default certificate, as on the production server) --------------
cat default.key default.pem > /etc/ssl/private/default-chain.pem; chmod 600 /etc/ssl/private/default-chain.pem
postconf -e "smtpd_tls_chain_files=/etc/ssl/private/default-chain.pem" "smtpd_tls_security_level=may" \
	"maillog_file=/var/log/postfix.log" "inet_interfaces=loopback-only" "myhostname=mx.test.local"
postconf -X tls_server_sni_maps 2>/dev/null
cat > /etc/dovecot/conf.d/10-ssl.conf <<EOC
ssl = required
ssl_cert = </src/dummy
EOC
sed -i "s#</src/dummy#<$W/default.pem\nssl_key = <$W/default.key#" /etc/dovecot/conf.d/10-ssl.conf
echo 'protocols = imap pop3' > /etc/dovecot/local.conf
cp /etc/postfix/main.cf main.cf.orig; cp /etc/dovecot/conf.d/10-ssl.conf 10-ssl.conf.orig
doveconf -n >/dev/null || { echo "dovecot base config broken"; exit 1; }
postfix start 2>/dev/null; dovecot; sleep 2

served() { # proto hostname -> CN of served certificate
	local opt="-connect 127.0.0.1:993"; [ "$1" = smtp ] && opt="-starttls smtp -connect 127.0.0.1:25"
	echo QUIT | timeout 10 openssl s_client $opt -servername $2 2>/dev/null | openssl x509 -noout -subject -fingerprint -sha256 2>/dev/null | tr '\n' ' '
}
state() { # enabled cert-of-example.de
	cat > state.json <<EOJ
{"enabled":"$1","domains":{
 "1":{"domain":"example.de","cert":"$W/$2.pem","key":"$W/$2.key","chain":"$W/ca.pem"},
 "2":{"domain":"example.org","cert":"$W/org.pem","key":"$W/org.key","chain":"$W/ca.pem"$3},
 "3":{"domain":"broken.de","cert":"$W/bad.pem","key":"$W/bad.key","chain":"$W/ca.pem"},
 "4":{"domain":"nocert.de"}}}
EOJ
}
sync() { php /src/tests/MailSni/integration/integration.php state.json | tee sync.log; sleep 2; }

echo "=== 1. initial sync (tls_server_sni_maps not set yet) ==="
state 1 ex ""; sync
[ "$(postconf -h tls_server_sni_maps)" = "hash:/etc/postfix/99-froxlor.map" ] && ok "tls_server_sni_maps set" || fail "tls_server_sni_maps"
[ "$(stat -c %a /etc/postfix/99-froxlor.map.db)" = 600 ] && ok ".db mode 600" || fail ".db mode $(stat -c %a /etc/postfix/99-froxlor.map.db)"
[ "$(stat -c %a /etc/ssl/froxlor-mail-sni/mail.example.de.key)" = 600 ] && ok "key mode 600" || fail "key mode"
postmap -F -q mail.example.de hash:/etc/postfix/99-froxlor.map | grep -q "PRIVATE KEY" && ok "postmap -F embeds key" || fail "postmap -F"
grep -q broken /etc/postfix/99-froxlor.map && fail "broken pair in map" || ok "invalid key/cert pair skipped"
grep -c "^local_name" /etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf | grep -qx 2 && ok "2 local_name blocks" || fail "local_name count"
for p in smtp imap; do
	served $p mail.example.de | grep -q "CN = example.de" && ok "$p SNI mail.example.de -> example.de cert" || fail "$p mail.example.de: $(served $p mail.example.de)"
	served $p mail.example.org | grep -q "CN = example.org" && ok "$p SNI mail.example.org -> example.org cert" || fail "$p mail.example.org"
	served $p unknown.test | grep -q "CN = mx.test.local" && ok "$p unknown name -> default cert" || fail "$p default: $(served $p unknown.test)"
done
OLDFP=$(served smtp mail.example.de)

echo "=== 2. repeated run without changes ==="
M1=$(stat -c %Y /etc/postfix/99-froxlor.map.db); sync
grep -q '"postfix":"unchanged","dovecot":"unchanged"' sync.log && ok "idempotent, no reload" || fail "not idempotent"
[ "$M1" = "$(stat -c %Y /etc/postfix/99-froxlor.map.db)" ] && ok "table not rebuilt" || fail "table rebuilt"

echo "=== 3. renewal (same paths, new certificate) ==="
state 1 ex2 ""; sync
NEWFP=$(served smtp mail.example.de)
[ "$OLDFP" != "$NEWFP" ] && echo "$NEWFP" | grep -q "CN = example.de" && ok "postfix serves renewed cert" || fail "postfix renewal"
[ "$(served imap mail.example.de)" = "$NEWFP" ] && ok "dovecot serves renewed cert" || fail "dovecot renewal"

echo "=== 4. removal of a mail domain (example.org no longer email domain) ==="
state 1 ex2 ',"extra":{"isemaildomain":0}'; sync
served smtp mail.example.org | grep -q "CN = mx.test.local" && ok "postfix: removed -> default cert" || fail "postfix removal"
served imap mail.example.org | grep -q "CN = mx.test.local" && ok "dovecot: removed -> default cert" || fail "dovecot removal"
[ ! -e /etc/ssl/froxlor-mail-sni/mail.example.org.key ] && ok "stale key removed" || fail "stale key"

echo "=== 5. invalid generated configuration is rolled back (simulated by broken base config) ==="
cp /etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf good.conf
state 1 ex ""                       # change -> rewrite required
echo "this_is_not_valid = " >> /etc/dovecot/local.conf
sync
grep -q '"dovecot":"failed"' sync.log && ok "doveconf -n failure detected" || fail "doveconf failure not detected"
cmp -s good.conf /etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf && ok "dovecot file restored" || fail "dovecot not restored"
pgrep -x dovecot >/dev/null && ok "dovecot still running" || fail "dovecot died"
echo 'protocols = imap pop3' > /etc/dovecot/local.conf
sync
grep -q '"dovecot":"updated"' sync.log && ok "next run recovers" || fail "no recovery"

echo "=== 6. feature disabled ==="
state 0 ex ""; sync
grep -q "^mail\." /etc/postfix/99-froxlor.map && fail "entries left in map" || ok "map emptied"
grep -q local_name /etc/dovecot/conf.d/99-froxlor-vhost.ssl.conf && fail "local_name left" || ok "dovecot emptied"
served smtp mail.example.de | grep -q "CN = mx.test.local" && ok "postfix default cert after disable" || fail "postfix after disable"
served imap mail.example.de | grep -q "CN = mx.test.local" && ok "dovecot default cert after disable" || fail "dovecot after disable"
postfix check && ok "postfix check clean" || fail "postfix check"
grep -q "smtpd_tls_chain_files = /etc/ssl/private/default-chain.pem" /etc/postfix/main.cf && ok "default certificate unchanged" || fail "default cert changed"
cmp -s 10-ssl.conf.orig /etc/dovecot/conf.d/10-ssl.conf && ok "dovecot default ssl config unchanged" || fail "10-ssl.conf changed"
ls /etc/ssl/froxlor-mail-sni/backups/ | grep -q . && ok "backups created" || fail "no backups"
pgrep -x dovecot >/dev/null && pgrep -f postfix/sbin/master >/dev/null && ok "services still running" || fail "service down"

echo; [ $FAILS -eq 0 ] && echo "ALL INTEGRATION CHECKS PASSED" || echo "$FAILS INTEGRATION CHECK(S) FAILED"
exit $FAILS
