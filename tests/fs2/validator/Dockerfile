FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY csv_validator.py /validator.py
USER 1001:1001
ENTRYPOINT ["/usr/bin/python3", "-I", "/validator.py"]
