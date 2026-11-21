# Czujka: developer and product targets.
SHELL := /bin/sh
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMPOSE := docker compose -f deploy/docker-compose.yml

# The development and test database: PostgreSQL 17 with pg_tde, bound to 127.0.0.1 only.
DEV_DB_NAME ?= czujka-dev-pg
DEV_DB_PORT ?= 55432
DEV_DB_URL  ?= postgres://czujka:czujka@127.0.0.1:$(DEV_DB_PORT)/czujka?sslmode=disable

.PHONY: help dev dev-db dev-db-stop test test-integration bench build web fmt up down logs clean e2e-core e2e-full

help:
	@echo "make dev              start the dev database and run czujka on http://127.0.0.1:8080"
	@echo "make test             gofmt check, build, vet, unit tests (database tests skip without a database)"
	@echo "make test-integration all tests against a real PostgreSQL with pg_tde in docker"
	@echo "make bench            ingest benchmark: 10 000 hosts x 3 services"
	@echo "make build            build the UI (when web/ exists) and bin/czujka"
	@echo "make up / down / logs the product stack from deploy/docker-compose.yml"
	@echo "make e2e-core         end-to-end check without a scan: import, analysis, diff, DefectDojo, exports (needs lab/defectdojo)"
	@echo "make e2e-full         full end-to-end check: real scans of a docker lab through the REST API (e2e/full)"

dev-db:
	@docker image inspect czujka-db:17 >/dev/null 2>&1 || docker build -t czujka-db:17 deploy/db
	@docker start $(DEV_DB_NAME) >/dev/null 2>&1 || docker run -d --name $(DEV_DB_NAME) \
		-e POSTGRES_USER=czujka -e POSTGRES_PASSWORD=czujka -e POSTGRES_DB=czujka \
		-p 127.0.0.1:$(DEV_DB_PORT):5432 -v $(DEV_DB_NAME)-keys:/tde-keys czujka-db:17 >/dev/null
	@echo "waiting for the database..."; \
	for i in $$(seq 1 60); do \
		docker exec $(DEV_DB_NAME) psql -h 127.0.0.1 -U czujka -d czujka -Atc "SELECT 1 FROM pg_extension WHERE extname = 'pg_tde'" 2>/dev/null | grep -q 1 && exit 0; sleep 1; \
	done; echo "the database did not start"; exit 1

dev-db-stop:
	-docker rm -f -v $(DEV_DB_NAME)
	-docker volume rm $(DEV_DB_NAME)-keys

dev: dev-db
	CZUJKA_DB_URL='$(DEV_DB_URL)' CZUJKA_MASTER_KEY_FILE=.dev-master.key CZUJKA_LOG_FORMAT=text \
	CZUJKA_ADMIN_EMAIL=$${CZUJKA_ADMIN_EMAIL:-admin@czujka.local} CZUJKA_LISTEN=127.0.0.1:8080 \
	CZUJKA_WEB_DIR=$${CZUJKA_WEB_DIR:-web/dist} go run -ldflags "-X main.version=$(VERSION)" ./cmd/czujka serve

test:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go build ./...
	go vet ./...
	go test ./...

test-integration: dev-db
	CZUJKA_TEST_DB_URL='$(DEV_DB_URL)' CZUJKA_TEST_REQUIRE_TDE=1 go test -count=1 ./...

bench: dev-db
	CZUJKA_TEST_DB_URL='$(DEV_DB_URL)' CZUJKA_BENCH=1 go test -count=1 -run 'TestIngestBenchmark|TestHTTPBenchmark' -v ./internal/store/ ./internal/api/

web:
	@if [ -f web/package.json ]; then cd web && npm install && npm run build; else echo "web/ is not present: skipping the UI build"; fi

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/czujka ./cmd/czujka

fmt:
	gofmt -w cmd internal

up:
	CZUJKA_VERSION=$(VERSION) $(COMPOSE) up -d --build --wait
	@$(COMPOSE) ps
	@echo "Czujka: http://127.0.0.1:$${CZUJKA_PORT:-8080}  (first administrator password: make logs | grep -A3 'first administrator')"

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --tail=200 czujka

e2e-core:
	bash deploy/e2e-core.sh

e2e-full:
	bash e2e/full/run.sh

clean:
	rm -rf bin .dev-master.key
