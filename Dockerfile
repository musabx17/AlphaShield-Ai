FROM python:3.10-slim

WORKDIR /app

# Upgrade pip and build tools first to handle modern wheel metadata cleanly
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements file
COPY Backend/requirements.txt .

# Install dependencies with explicit timeout and index retries
RUN pip install --no-cache-dir --default-timeout=1000 --retries 10 -r requirements.txt

# Copy application files
COPY . .

ENV PYTHONPATH=/app/Backend

EXPOSE 8000

CMD ["uvicorn", "main:app", "--app-dir", "Backend", "--host", "0.0.0.0", "--port", "8000"]