FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Generate a self-signed cert for HTTPS. The proxy's upstream transport
# skips verification, so the cert just needs to exist.
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /app/key.pem -out /app/cert.pem -days 3650 -nodes \
    -subj "/CN=target.local" \
    -addext "subjectAltName=DNS:target.local,DNS:*.target.local,DNS:localhost"

COPY . .

EXPOSE 443

CMD ["python", "app.py"]
