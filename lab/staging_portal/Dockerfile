FROM nginx:alpine

RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs \
    && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout /etc/nginx/certs/staging.key \
       -out /etc/nginx/certs/staging.crt \
       -subj "/C=PL/O=AGH CBI/CN=staging-portal.agh.local" \
       -addext "subjectAltName=DNS:staging-portal.agh.local,DNS:admin-staging.agh.local,IP:172.28.0.12"
