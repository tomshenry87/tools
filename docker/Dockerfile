# Use official Python 3.10 base image (Debian-based)
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system-level dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libpython3-dev \
    libdbus-1-dev \
    libgirepository1.0-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy your scripts into the container
COPY . .

# Default to an interactive bash shell
CMD ["/bin/bash"]
