#!/bin/bash
# Lets the stock entrypoint copy WordPress and write wp-config.php, then
# installs the site with wp-cli so the lab host is a working WordPress.
set -e
docker-entrypoint.sh apache2 -v >/dev/null

until php -r 'exit(@mysqli_connect(getenv("WORDPRESS_DB_HOST"), getenv("WORDPRESS_DB_USER"), getenv("WORDPRESS_DB_PASSWORD"), getenv("WORDPRESS_DB_NAME")) ? 0 : 1);'; do
  echo "lab: waiting for the database"
  sleep 2
done

WP="wp --allow-root --path=/var/www/html"
if ! $WP core is-installed 2>/dev/null; then
  $WP core install --url="$LAB_URL" --title="$LAB_TITLE" --admin_user=labadmin \
    --admin_password="$LAB_ADMIN_PASSWORD" --admin_email=admin@example.com --skip-email
  $WP option update blogdescription "" >/dev/null 2>&1 || true
fi
chown -R www-data:www-data /var/www/html/wp-content
touch /tmp/lab-installed
exec docker-entrypoint.sh "$@"
