FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.0 gunicorn==21.2.0
COPY app.py boot.sh ./
RUN chmod +x boot.sh

EXPOSE 80 9090 3100
CMD ["./boot.sh"]
