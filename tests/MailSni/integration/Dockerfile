# Test image matching the target production stack:
# Ubuntu 22.04 / PHP 8.1 / Postfix 3.6.4 / Dovecot 2.3.16
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections \
 && echo "postfix postfix/mailname string mx.test.local" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      php8.1-cli php8.1-xml php8.1-mbstring php8.1-curl php8.1-zip php8.1-mysql php8.1-intl php8.1-bcmath php8.1-gmp php8.1-gd \
      postfix dovecot-imapd dovecot-pop3d openssl ca-certificates unzip git curl \
 && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
