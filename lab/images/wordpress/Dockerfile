# WordPress that installs itself on first start (no setup screen).
ARG WP_TAG
FROM wordpress:${WP_TAG}
ADD --chmod=755 https://github.com/wp-cli/wp-cli/releases/download/v2.12.0/wp-cli-2.12.0.phar /usr/local/bin/wp
COPY --chmod=755 lab-entrypoint.sh /usr/local/bin/lab-entrypoint.sh
ENTRYPOINT ["lab-entrypoint.sh"]
CMD ["apache2-foreground"]
