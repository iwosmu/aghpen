# Drupal installed at build time on SQLite, so the host shows a real site.
FROM drupal:10.6.22-php8.3-apache
RUN cd /opt/drupal/web \
 && php core/scripts/drupal install standard --site-name="Repozytorium Prac Dyplomowych" --no-interaction \
 && chown -R www-data:www-data /opt/drupal/web/sites
