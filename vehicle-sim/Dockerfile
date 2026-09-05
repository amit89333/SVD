FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vehicle-sim/ ./vehicle-sim/

ENV PYTHONUNBUFFERED=1

CMD ["python", "vehicle-sim/ecu_gateway.py"]
