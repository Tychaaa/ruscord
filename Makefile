.PHONY: up down logs

up:
	docker compose --env-file .env -f infra/docker-compose.yml up -d

down:
	docker compose --env-file .env -f infra/docker-compose.yml down

logs:
	docker compose --env-file .env -f infra/docker-compose.yml logs -f