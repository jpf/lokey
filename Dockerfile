FROM python:2.7-alpine

RUN apk add --no-cache \
  gcc \
  musl-dev \
  libffi-dev \
  openssl-dev

RUN pip install lokey
entrypoint ["lokey"]
