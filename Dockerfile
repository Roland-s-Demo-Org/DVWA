FROM docker.io/library/php:8-apache
WORKDIR /var/www/html

# https://www.php.net/manual/en/image.installation.php
RUN apt-get update \
 && apt-get install -y zlib1g-dev libpng-dev libjpeg-dev libfreetype6-dev iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-configure gd --with-jpeg --with-freetype \
 # Use pdo_sqlite instead of pdo_mysql if you want to use sqlite
 && docker-php-ext-install gd mysqli pdo pdo_mysql

# Create non-root user and set ownership
RUN (which useradd || apt-get update && apt-get install -y passwd) && \
    (useradd -u 1000 appuser || true) && \
    (chown -R 1000:1000 /var/www/html)

COPY --chown=1000:1000 . .
COPY --chown=1000:1000 config/config.inc.php.dist config/config.inc.php

# Switch to non-root user
USER 1000
