#!/usr/bin/env python3
"""Static Lambda proxy (guardrail-first).

Deployment:
- `LINKED_ASSET_URL` is a build-time placeholder; replace in your pipeline.
- `GUARDRAIL_VALUE` is a runtime env var (required).

Behavior:
- Validate `x-amz-security-token` against `GUARDRAIL_VALUE`.
- Return 403 on failure; otherwise proxy to {LINKED_ASSET_URL}/v2/<path>.
"""
import os
import sys
import logging
import typing
import base64
import json
import urllib.parse
import urllib.request
import urllib.error

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Deployment-time placeholder; replace in pipeline.
LINKED_ASSET_URL = "{{ linked_asset_a_record }}"

# Runtime-only secret guardrail: set this as an environment variable on the Lambda.
GUARDRAIL_VALUE = os.environ.get('GUARDRAIL_VALUE', '').strip()
DEBUG = bool(os.environ.get('DEBUG'))

# Request timeout (seconds)
TIMEOUT_SECONDS = 30

# Stdlib-only proxy that enforces the guardrail header.

# Fail early if LINKED_ASSET_URL not replaced or guardrail missing.
if not LINKED_ASSET_URL or LINKED_ASSET_URL.startswith('{{'):
    print('ERROR: LINKED_ASSET_URL placeholder was not replaced. Embed your Terraform variable into this file before deploying.')
    sys.exit(2)

if not GUARDRAIL_VALUE:
    print('ERROR: GUARDRAIL_VALUE environment variable is not set. This must contain the shared secret guardrail token.')
    sys.exit(2)

# Ensure LINKED_ASSET_URL has a scheme
if not LINKED_ASSET_URL.startswith('http://') and not LINKED_ASSET_URL.startswith('https://'):
    LINKED_ASSET_URL = 'https://' + LINKED_ASSET_URL

# Guardrail header name comes from Terraform, with the current default as a fallback.
GUARDRAIL_HEADER = '{{ guardrail_header }}'.strip()
if not GUARDRAIL_HEADER or GUARDRAIL_HEADER.startswith('{{'):
    GUARDRAIL_HEADER = 'x-amz-security-token'


def normalize_headers(headers: typing.Optional[typing.Dict[str, str]]) -> typing.Dict[str, str]:
    if not headers:
        return {}
    return {k.lower(): v for k, v in headers.items()}


def filter_headers_for_forwarding(headers: typing.Dict[str, str]) -> typing.Dict[str, str]:
    aws_headers = {
        'x-amzn-trace-id',
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-forwarded-port',
        'x-amz-apigw-id',
    }
    # Strip common AWS infra headers; keep profile headers (Host, guardrail, etc.).
    return {k: v for k, v in headers.items() if k.lower() not in aws_headers}


def build_proxy_url(base: str, path: str, raw_query: str) -> str:
    # Ensure path starts with /v2/
    if not path.startswith('/v2/'):
        if path.startswith('/'):
            path = '/v2' + path
        else:
            path = '/v2/' + path

    # Join base and path
    if base.endswith('/') and path.startswith('/'):
        base = base[:-1]

    url = base + path
    if raw_query:
        url = url + '?' + raw_query
    return url
# Outbound requests use urllib.request.urlopen.


def lambda_handler(event: typing.Dict, context: typing.Any) -> typing.Dict:
    """API Gateway -> Lambda handler (supports v2 payload format and legacy v1 fields)."""
    try:
        # HTTP method
        method = (event.get('requestContext', {}) .get('http', {}) .get('method')
                  or event.get('httpMethod') or 'GET')

        # Path and raw query string (prefer rawPath/rawQueryString to preserve exact encoding)
        path = event.get('rawPath') or event.get('path') or '/'
        raw_query = event.get('rawQueryString')
        if raw_query is None:
            qdict = event.get('queryStringParameters') or {}
            raw_query = urllib.parse.urlencode(qdict) if qdict else ''

        headers = normalize_headers(event.get('headers') or {})

        logger.info(f"Received request: {method} {path}?{raw_query}")
        if DEBUG:
            # Debug prints (guardrail hidden)
            safe_headers = {k: v for k, v in (event.get('headers') or {}).items() if k.lower() != GUARDRAIL_HEADER}
            print('--- DEBUG REQUEST ---')
            print('Method:', method)
            print('Path:', path)
            print('Raw query:', raw_query)
            print('Headers (safe):', safe_headers)
            body_preview = event.get('body')
            if body_preview:
                try:
                    size = len(body_preview)
                except Exception:
                    size = 'unknown'
            else:
                size = 0
            print('Body length (chars or bytes):', size)
            print('isBase64Encoded:', bool(event.get('isBase64Encoded')))
            print('---')

        # Enforce guardrail
        if headers.get(GUARDRAIL_HEADER) != GUARDRAIL_VALUE:
            logger.warning('Guardrail check failed for request: %s %s', method, path)
            # Return a legitimate-looking 403 JSON response
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'message': 'Forbidden'}),
                'isBase64Encoded': False
            }

        # Build proxy URL
        proxy_url = build_proxy_url(LINKED_ASSET_URL, path, raw_query)

        # Prepare request body
        body = event.get('body')
        is_base64 = bool(event.get('isBase64Encoded'))
        if is_base64 and body:
            try:
                data = base64.b64decode(body)
            except Exception:
                logger.exception('Failed to decode base64 body')
                data = b''
        elif body:
            data = body.encode('utf-8') if isinstance(body, str) else body
        else:
            data = None

        # Filter infra headers
        forward_headers = filter_headers_for_forwarding(event.get('headers') or {})

        # Create request using urllib and forward to upstream
        req = urllib.request.Request(proxy_url, data=data, headers=forward_headers, method=method)

        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS)
        except urllib.error.HTTPError as e:
            resp = e
        except urllib.error.URLError:
            logger.exception('Upstream network error')
            return {
                'statusCode': 502,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'message': 'Bad Gateway'}),
                'isBase64Encoded': False,
            }

        resp_body = resp.read()
        resp_headers = dict(resp.headers) if hasattr(resp, 'headers') else {}
        status = getattr(resp, 'status', getattr(resp, 'code', 502))

        # Decide whether to base64-encode response body
        try:
            text = resp_body.decode('utf-8')
            if DEBUG:
                print('--- DEBUG RESPONSE ---')
                print('Status:', status)
                print('Response headers:', resp_headers)
                print('Body length (bytes):', len(resp_body))
                print('---')
            return {
                'statusCode': status,
                'headers': resp_headers,
                'body': text,
                'isBase64Encoded': False
            }
        except Exception:
            b64 = base64.b64encode(resp_body).decode('ascii')
            if DEBUG:
                print('--- DEBUG RESPONSE ---')
                print('Status:', status)
                print('Response headers:', resp_headers)
                print('Body length (bytes):', len(resp_body))
                print('isBase64Encoded: True (returning base64)')
                print('---')
            return {
                'statusCode': status,
                'headers': resp_headers,
                'body': b64,
                'isBase64Encoded': True
            }

    except Exception:
        logger.exception('Unhandled error in lambda_handler')
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'message': 'Internal Server Error'}),
            'isBase64Encoded': False
        }


if __name__ == '__main__':
    print('This file is intended to be deployed as an AWS Lambda function.')
