# Use Python 3.9 slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create necessary directories
RUN mkdir -p logs reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV CONFIG_PATH=config/config.yaml

# Expose ports (if needed for future web interface)
# EXPOSE 8000

# Run the application
CMD ["python", "-m", "src.main"]
