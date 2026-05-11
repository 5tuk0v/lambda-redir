#!/usr/bin/env python3
import base64
import os
import ssl
import sys
import urllib.error
import urllib.request

LINKED_ASSET_URL = "{{ linked_asset_a_record }}"
GUARDRAIL_VALUE = os.environ.get('GUARDRAIL_VALUE', '').strip()
GUARDRAIL_HEADER = os.environ.get('GUARDRAIL_HEADER', '{{ guardrail_header }}').strip() or 'x-amz-security-token'
DEBUG = bool(os.environ.get('DEBUG'))
COOKIE_REBUILD_FROM_EVENT = bool(os.environ.get('COOKIE_REBUILD_FROM_EVENT'))

if not LINKED_ASSET_URL or LINKED_ASSET_URL.startswith('{' + '{'):
    print('ERROR: LINKED_ASSET_URL placeholder was not replaced.')
    sys.exit(2)
if not GUARDRAIL_VALUE:
    print('ERROR: GUARDRAIL_VALUE environment variable is not set.')
    sys.exit(2)

if not LINKED_ASSET_URL.startswith(('http://', 'https://')):
    LINKED_ASSET_URL = 'https://' + LINKED_ASSET_URL


def lambda_handler(event, context):
    method = event['requestContext']['http']['method']
    path = event['rawPath']
    query_string = event.get('rawQueryString')
    headers = event.get('headers', {})
    body = event.get('body')
    is_base64_encoded = event['isBase64Encoded']
    stage = event.get('requestContext', {}).get('stage', 'v2')

    if DEBUG:
        print(f'[DEBUG] Full event: {event}')
        print(f'[DEBUG] {method} {path}')
        if 'Cookie' in headers or 'cookie' in headers:
            cookie_key = 'Cookie' if 'Cookie' in headers else 'cookie'
            print(f'[DEBUG] Original Cookie header: {headers[cookie_key]}')

    guardrail = next((v for k, v in headers.items() if k.lower() == GUARDRAIL_HEADER.lower()), None)
    if guardrail != GUARDRAIL_VALUE:
        if DEBUG:
            print(f'[DEBUG] Guardrail check failed: got {guardrail!r}')
        return {'statusCode': 403, 'body': 'Forbidden'}

    if DEBUG:
        print('[DEBUG] Guardrail validated')

    if not path.startswith(f'/{stage}/'):
        if path.startswith('/'):
            path = f'/{stage}' + path
        else:
            path = f'/{stage}/' + path

    if query_string:
        upstream_url = f'{LINKED_ASSET_URL}{path}?{query_string}'
    else:
        upstream_url = f'{LINKED_ASSET_URL}{path}'

    if is_base64_encoded and body:
        try:
            body = base64.b64decode(body)
        except Exception:
            print('[!] Failed to decode base64 body.')

    forwarded_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in ['x-amzn-trace-id', 'x-forwarded-port', 'x-forwarded-proto', 'host', GUARDRAIL_HEADER.lower()]
    }

    if COOKIE_REBUILD_FROM_EVENT:
        event_cookies = event.get('cookies')
        if isinstance(event_cookies, list) and event_cookies:
            cookie_parts = [str(cookie).strip() for cookie in event_cookies if str(cookie).strip()]
            if cookie_parts:
                cookie_header_key = next((k for k in forwarded_headers if k.lower() == 'cookie'), 'Cookie')
                forwarded_headers[cookie_header_key] = '; '.join(cookie_parts)
                if DEBUG:
                    print(f'[DEBUG] Rebuilt Cookie from event.cookies: {forwarded_headers[cookie_header_key]}')

    if DEBUG:
        print(f'*** Beacon -> TS ***\nMethod: {method}\nURL: {upstream_url}\nHeaders: {forwarded_headers}\nBody: {body}\nisBase64Encoded: {is_base64_encoded}')

    if isinstance(body, str):
        data = body.encode('utf-8')
    else:
        data = body

    request = urllib.request.Request(
        upstream_url,
        data=data,
        headers=forwarded_headers,
        method=method,
    )

    ssl_context = ssl._create_unverified_context()

    try:
        response = urllib.request.urlopen(request, timeout=10, context=ssl_context)
        status = response.status
    except urllib.error.HTTPError as error:
        response = error
        status = error.code
    except urllib.error.URLError as error:
        print(f'[!] Failed to forward request to TS: {str(error)}')
        return {'statusCode': 403}

    response_body = response.read()
    response_text = response_body.decode('utf-8')

    if DEBUG:
        print(f'*** Beacon <- TS ***\nStatus code: {status}\nHeaders: {dict(response.headers)}\nBody: {response_text}\n')

    return {
        'statusCode': status,
        'headers': dict(response.headers),
        'body': response_text,
    }