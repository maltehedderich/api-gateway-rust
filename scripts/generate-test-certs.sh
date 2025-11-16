#!/bin/bash

# Script to generate self-signed certificates for testing
# DO NOT use these certificates in production!

set -e

CERT_DIR="certs"

echo "Generating self-signed certificates for testing..."

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Generate private key
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# Generate self-signed certificate
openssl req -new -x509 \
    -key "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

echo "Certificates generated successfully!"
echo "Certificate: $CERT_DIR/cert.pem"
echo "Private Key: $CERT_DIR/key.pem"
echo ""
echo "To use these certificates, set the following environment variables:"
echo "  export GATEWAY_TLS_CERT_PATH=\$(pwd)/$CERT_DIR/cert.pem"
echo "  export GATEWAY_TLS_KEY_PATH=\$(pwd)/$CERT_DIR/key.pem"
echo ""
echo "WARNING: These are self-signed certificates for testing only!"
echo "Do NOT use in production!"
