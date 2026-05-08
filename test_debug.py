#!/usr/bin/env python3
"""Test harness to validate DEBUG redaction."""
import os
import json
import base64
import sys

# Set env vars before importing the handler
os.environ['GUARDRAIL_VALUE'] = 'secret-token'
os.environ['DEBUG'] = '1'

# Read static_lambda, replace placeholder, then import
with open('static_lambda.py', 'r') as f:
    code = f.read()
code = code.replace('{{ linked_asset_a_record }}', 'https://127.0.0.1')
code = code.replace('{{ guardrail_header }}', 'x-amz-security-token')

exec(code, globals())

from unittest.mock import patch, MagicMock

# Test case: plain body with guardrail and infra headers
event = {
    "version": "2.0",
    "rawPath": "/beacon/check",
    "rawQueryString": "id=xyz",
    "headers": {
        "x-amz-security-token": "secret-token",  # GUARDRAIL — must be redacted
        "User-Agent": "Beacon/1.0",
        "x-amzn-trace-id": "Root=1-abc",  # AWS infra — must be redacted
        "Host": "redirector.example.com"
    },
    "requestContext": {
        "http": {"method": "POST"},
        "stage": "prod"
    },
    "body": '{"task":"check","id":"abc123"}',
    "isBase64Encoded": False
}

print("\n=== Test: Plain body with redactable headers ===")
# Mock the upstream response to avoid network error
with patch('urllib.request.urlopen') as mock_urlopen:
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.code = 200
    mock_resp.headers = {'Content-Type': 'text/plain'}
    mock_resp.read.return_value = b'OK'
    mock_urlopen.return_value = mock_resp

    resp = lambda_handler(event, None)
    print(f"Response status: {resp['statusCode']}\n")

# Test case 2: Binary base64 body
binary_data = b"\x00\x01\x02\x03BEACON_DATA\xff\xfe"
b64_body = base64.b64encode(binary_data).decode('ascii')

event2 = {
    "version": "2.0",
    "rawPath": "/upload",
    "rawQueryString": "",
    "headers": {
        "x-amz-security-token": "secret-token",  # GUARDRAIL
        "Content-Type": "application/octet-stream"
    },
    "requestContext": {"http": {"method": "PUT"}},
    "body": b64_body,
    "isBase64Encoded": True
}

print("=== Test: Binary base64 body ===")
with patch('urllib.request.urlopen') as mock_urlopen:
    mock_resp = MagicMock()
    mock_resp.status = 201
    mock_resp.code = 201
    mock_resp.headers = {'Content-Type': 'application/json'}
    mock_resp.read.return_value = b'{"success": true}'
    mock_urlopen.return_value = mock_resp

    resp2 = lambda_handler(event2, None)
    print(f"Response status: {resp2['statusCode']}\n")
