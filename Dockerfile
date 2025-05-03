FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential libpq-dev && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --upgrade pip && pip install uv

# Create and activate a virtual environment
RUN python -m venv .venv

# Set environment variables for the virtual environment
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install Python dependencies with uv (using the activated venv)
RUN . .venv/bin/activate && uv pip install -r <(uv pip compile pyproject.toml)

# Copy project files
COPY . .

# Expose port
EXPOSE 8000

# Run migrations and start server (using the activated venv)
CMD ["/bin/bash", "-c", ". .venv/bin/activate && python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]