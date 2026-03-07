FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src

# Copy .env file for API keys
COPY .env ./src/.env

# Copy test file for running tests inside container
COPY test.py ./test.py

# Expose port for API server
EXPOSE 5000

# Set working directory to src for imports
WORKDIR /app/src

# Run as API server by default on port 5000
# Endpoints will be available at /api/Recon-Analyzer/*
# Examples:
#   POST /api/Recon-Analyzer/scan - Scan IP or domain
#   POST /api/Recon-Analyzer/footprint - Digital footprint analysis
#   GET  /api/Recon-Analyzer/health - Health check
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "main:app"]