FROM python:3.11-alpine

# Copy the connector
COPY . /opt/opencti-connector-kaspersky

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-kaspersky && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]