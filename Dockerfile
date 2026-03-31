# 1st Stage: Build
FROM python:3.10-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# 2nd Stage: Runtime 
FROM python:3.10-slim

WORKDIR /app

# Only necessary libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Builder stage's libraries
COPY --from=builder /root/.local /root/.local
COPY . .

ENV PATH=/root/.local/bin:$PATH

CMD ["python", "app/main.py"]

# Separated stages for establishing Kubernetes pod efficiency and minimal delay for pod opening/closing operations.