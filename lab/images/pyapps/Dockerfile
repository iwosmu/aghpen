# One image for the two Python hosts: Django in debug mode and Flask behind gunicorn.
FROM python:3.13.18-alpine
RUN pip install --no-cache-dir "Django==5.2.*" "Flask==3.1.*" "gunicorn==23.*"
WORKDIR /app
RUN mkdir django && django-admin startproject labsite django \
 && sed -i "s/^ALLOWED_HOSTS = .*/ALLOWED_HOSTS = ['*']/" django/labsite/settings.py \
 && grep -q "^DEBUG = True" django/labsite/settings.py \
 && python django/manage.py migrate --noinput
COPY flask /app/flask
