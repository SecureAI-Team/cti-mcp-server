FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MITRE_CACHE_DIR=/app/.mitre_cache

# Create a non-root user for security
RUN groupadd -g 1000 appgroup && \
    useradd -u 1000 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

# Install system dependencies and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project definition and source code
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the application
RUN pip install --no-cache-dir .

# Create directories and set permissions
RUN mkdir -p ${MITRE_CACHE_DIR} /app/logs && \
    chown -R appuser:appgroup /app ${MITRE_CACHE_DIR}

# Switch to non-root user for executing the application
USER appuser

# Expose port for HTTP transport
EXPOSE 8000

# Healthcheck to verify the backend is listening
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -s http://localhost:8000/ > /dev/null || exit 1

# Default command to start MCP server over HTTP transport
CMD ["cti-mcp", "--transport=http"]
