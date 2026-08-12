FROM python:3.11-slim

WORKDIR /app

# Copy requirements first so Docker can cache this layer separately —
# dependencies only get reinstalled if requirements.txt actually changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8001

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
