# Use the official Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY python-worker/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the worker code
COPY python-worker/ /app/

# Create data directory
RUN mkdir -p /app/data/tasks /app/data/results /app/data/reports

# Set permissions
RUN chmod +x /app/worker.py

# Run the worker API
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]
