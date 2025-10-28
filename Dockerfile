FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 42069

# Run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:42069", "app:app"]
