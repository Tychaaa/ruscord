#!/bin/sh
set -eu

mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"

# Создаём bucket, если нет
mc mb -p "local/$MINIO_BUCKET" || true

# Можно включить публичный доступ на MVP НЕ советую.
# Лучше раздавать signed URL из backend.
# mc anonymous set download "local/$MINIO_BUCKET" || true

echo "MinIO bucket ready: $MINIO_BUCKET"