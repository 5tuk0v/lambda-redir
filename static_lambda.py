#!/usr/bin/env python3
"""Static Lambda proxy (guardrail-first) with verbose DEBUG logging.

Deployment:
- `LINKED_ASSET_URL` is a build-time placeholder; replace in your pipeline.
- `GUARDRAIL_VALUE` is a runtime env var (required).
- `GUARDRAIL_HEADER` (Terraform placeholder) defines the header name; defaults to 'x-amz-security-token'.

Behavior:
- Validate the guardrail header against `GUARDRAIL_VALUE`; return 403 if missing/invalid.
- Filter AWS infrastructure headers (X-Amzn-Trace-Id, X-Forwarded-*, X-Amz-Apigw-Id) from forwarding.
- Proxy authenticated requests to {LINKED_ASSET_URL}/v2/<path> with the request body.
- Handle both plain-text and base64-encoded request/response bodies.
- Support multiValueHeaders, queryStringParameters, and pathParameters.

Debug Mode (DEBUG=1):
- Log full incoming request (headers redacted, body decoded/shown).
- Log full outgoing response (status, headers, body length).
- Guardail header is NEVER logged—it is redacted from all debug output.
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

# Request timeout (seconds)
TIMEOUT_SECONDS = 30

# Stdlib-only proxy that enforces the guardrail header.

# Fail early if LINKED_ASSET_URL not replaced or guardrail missing.
if not LINKED_ASSET_URL:
    print('ERROR: LINKED_ASSET_URL placeholder was not replaced. Embed your Terraform variable into this file before deploying.')
    sys.exit(2)

if not GUARDRAIL_VALUE:
    print('ERROR: GUARDRAIL_VALUE environment variable is not set. This must contain the shared secret guardrail token.')
    sys.exit(2)

# Ensure LINKED_ASSET_URL has a scheme
if not (LINKED_ASSET_URL.startswith('http://') or LINKED_ASSET_URL.startswith('https://')):
    LINKED_ASSET_URL = 'https://' + LINKED_ASSET_URL

# Guardrail header name comes from Terraform, with the current default as a fallback.
GUARDRAIL_HEADER = '{{ guardrail_header }}'.strip()
if not GUARDRAIL_HEADER:
    GUARDRAIL_HEADER = 'x-amz-security-token'

# Headers to strip from forwarding and to redact from DEBUG dumps.
# We include the guardrail header so it is not forwarded or logged.
INFRA_HEADERS = {
    'x-amzn-trace-id',
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-port',
    'x-amz-apigw-id',
}
INFRA_HEADERS.add(GUARDRAIL_HEADER.lower())


def _error_response(status_code: int, message: str) -> typing.Dict:
    """Build a JSON error response."""
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'message': message}),
        'isBase64Encoded': False
    }


def filter_headers_for_forwarding(headers: typing.Dict[str, str]) -> typing.Dict[str, str]:
    # Strip common AWS infra headers (and guardrail); keep profile headers.
    return {k: v for k, v in headers.items() if k.lower() not in INFRA_HEADERS}


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


def lambda_handler(event: typing.Dict, context: typing.Any) -> typing.Dict:
    """API Gateway -> Lambda handler (supports v2 payload format and legacy v1 fields)."""
    try:
        debug_enabled = bool(os.environ.get('DEBUG'))

        # HTTP method
        method = (event.get('requestContext', {}) .get('http', {}) .get('method')
                  or event.get('httpMethod') or 'GET')

        # Path and raw query string (prefer rawPath/rawQueryString to preserve exact encoding)
        path = event.get('rawPath') or event.get('path') or '/'
        raw_query = event.get('rawQueryString')
        if raw_query is None:
            qdict = event.get('queryStringParameters') or {}
            raw_query = urllib.parse.urlencode(qdict) if qdict else ''

        logger.info(f"Received request: {method} {path}?{raw_query}")
        
        # Check guardrail header (case-insensitive)
        headers_raw = event.get('headers') or {}
        guardrail_value = next(
            (v for k, v in headers_raw.items() if k.lower() == GUARDRAIL_HEADER),
            None
        )
        
        if debug_enabled:
            # Verbose debug dump — redact infra headers (including guardrail)
            # Note: INFRA_HEADERS keys are already lowercased
            headers_safe = {k: v for k, v in headers_raw.items() if k.lower() not in INFRA_HEADERS}

            mv_raw = event.get('multiValueHeaders') or {}
            mv_safe = {k: v for k, v in mv_raw.items() if k.lower() not in INFRA_HEADERS}

            qparams = event.get('queryStringParameters')
            pparams = event.get('pathParameters')

            req_body = event.get('body')
            is_b64 = bool(event.get('isBase64Encoded'))
            req_body_display = None
            if req_body is None or req_body == '':
                req_body_display = None
            else:
                if is_b64:
                    try:
                        decoded = base64.b64decode(req_body)
                        try:
                            req_body_display = decoded.decode('utf-8')
                        except Exception:
                            # Binary content — show base64 and decoded length
                            req_body_display = {
                                'base64': req_body,
                                'decoded_bytes_len': len(decoded)
                            }
                    except Exception:
                        req_body_display = {'base64_invalid': True, 'raw': req_body}
                else:
                    req_body_display = req_body if isinstance(req_body, str) else str(req_body)

            print('--- DEBUG REQUEST ---')
            print('Method:', method)
            print('Path:', path)
            print('Raw query:', raw_query)
            print('Headers (redacted):', headers_safe)
            if mv_safe:
                print('MultiValueHeaders (redacted):', mv_safe)
            if qparams is not None:
                print('QueryStringParameters:', qparams)
            if pparams is not None:
                print('PathParameters:', pparams)
            print('Body:', req_body_display)
            print('isBase64Encoded:', is_b64)
            print('---')

        # Enforce guardrail
        if guardrail_value != GUARDRAIL_VALUE:
            logger.warning('Guardrail check failed for request: %s %s', method, path)
            return _error_response(403, 'Forbidden')

        # Build proxy URL
        proxy_url = build_proxy_url(LINKED_ASSET_URL, path, raw_query)

        # Prepare request body
        req_body = event.get('body')
        is_base64 = bool(event.get('isBase64Encoded'))
        if is_base64 and req_body:
            try:
                data = base64.b64decode(req_body)
            except Exception:
                logger.exception('Failed to decode base64 body')
                data = b''
        elif req_body:
            data = req_body.encode('utf-8') if isinstance(req_body, str) else req_body
        else:
            data = None

        # Filter infra headers
        forward_headers = filter_headers_for_forwarding(headers_raw)

        # Create request using urllib and forward to upstream
        req = urllib.request.Request(proxy_url, data=data, headers=forward_headers, method=method)

        try:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS)
        except urllib.error.HTTPError as e:
            resp = e
        except urllib.error.URLError:
            logger.exception('Upstream network error')
            return _error_response(502, 'Bad Gateway')

        resp_body = resp.read()
        resp_headers = dict(resp.headers) if hasattr(resp, 'headers') else {}
        status = getattr(resp, 'status', getattr(resp, 'code', 502))

        # Decide whether to base64-encode response body
        is_base64_response = False
        try:
            body = resp_body.decode('utf-8')
        except Exception:
            body = base64.b64encode(resp_body).decode('ascii')
            is_base64_response = True

        if debug_enabled:
            print('--- DEBUG RESPONSE ---')
            print('Status:', status)
            print('Response headers:', resp_headers)
            print('Body length (bytes):', len(resp_body))
            print('isBase64Encoded:', is_base64_response)
            print('---')

        return {
            'statusCode': status,
            'headers': resp_headers,
            'body': body,
            'isBase64Encoded': is_base64_response
        }

    except Exception:
        logger.exception('Unhandled error in lambda_handler')
        return _error_response(500, 'Internal Server Error')


if __name__ == '__main__':
    print('This file is intended to be deployed as an AWS Lambda function.')
