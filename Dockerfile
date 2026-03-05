FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MITRE_CACHE_DIR=/app/.mitre_cache

WORKDIR /app

# Install system dependencies and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project definition and source code
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the application
RUN pip install --no-cache-dir .

# Create and set permissions for cache and logs directories
RUN mkdir -p ${MITRE_CACHE_DIR} /app/logs && chmod 777 ${MITRE_CACHE_DIR} /app/logs

# Expose port for HTTP transport
EXPOSE 8000

# Default command to start MCP server over HTTP transport
CMD ["cti-mcp", "--transport=http"]
