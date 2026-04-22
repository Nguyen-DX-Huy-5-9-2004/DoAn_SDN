FROM python:3.9-slim

# Cài đặt các công cụ mạng cơ bản
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping net-tools iproute2 curl \
    && rm -rf /var/lib/apt/lists/*

# Cài sẵn dependency để runtime không phụ thuộc Internet.
RUN pip install --no-cache-dir django psycopg2-binary psutil
WORKDIR /app
