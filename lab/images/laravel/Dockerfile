# A fresh Laravel application with debug mode on, served by "artisan serve".
FROM composer:2.11.2 AS build
RUN composer create-project --prefer-dist --no-interaction --no-progress laravel/laravel /app "12.*"

FROM php:8.4-cli-alpine
COPY --from=build /app /app
WORKDIR /app
RUN sed -i 's/^APP_DEBUG=.*/APP_DEBUG=true/; s/^APP_ENV=.*/APP_ENV=local/; s#^APP_URL=.*#APP_URL=http://10.66.3.15:8000#' .env \
 && echo "SESSION_COOKIE=laravel_session" >> .env \
 && php artisan migrate --force --no-interaction \
 && php artisan config:clear
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
