# Auth Service (gRPC)

[![CI](https://github.com/Tim73916/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/Tim73916/auth-service/actions/workflows/ci.yml)

gRPC сервис аутентификации на Go. JWT, регистрация, логин, проверка администратора.

## Технологии

- Go 1.25
- gRPC + Reflection
- JWT
- SQLite + migrations
- Bcrypt
- GitHub Actions (CI)

## Быстрый старт

```bash
git clone https://github.com/Tim73916/auth-service.git
cd auth-service

cp .env.example .env
cp config/local.yaml.example config/local.yaml

# Сгенерируйте JWT_SECRET
echo "JWT_SECRET=$(openssl rand -base64 32)" >> .env

# Миграции
mkdir -p storage
go run cmd/migrator/main.go \
    --storage-path=./storage/sso.db \
    --migrations-path=./migrations

# Запуск сервера
go run cmd/sso/main.go --config=./config/local.yaml
