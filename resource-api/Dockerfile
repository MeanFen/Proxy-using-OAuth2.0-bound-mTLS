FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8443

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-certfile", "/app/tls/resource-api.crt", "--ssl-keyfile", "/app/tls/resource-api.key", "--ssl-ca-certs", "/app/tls/service-ca.crt", "--ssl-cert-reqs", "2"]
