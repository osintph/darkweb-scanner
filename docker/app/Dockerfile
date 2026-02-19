FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything first, then install
COPY pyproject.toml ./
COPY src/ ./src/
COPY config/ ./config/

# Install the package
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[all]"

RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

EXPOSE 8080

CMD ["python", "-m", "darkweb_scanner.main", "--help"]
