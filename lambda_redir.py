#!/usr/bin/env python3
import base64
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

LINKED_ASSET_URL = "{{ linked_asset_a_record }}"
GUARDRAIL_VALUE = os.environ.get('GUARDRAIL_VALUE', '').strip()
GUARDRAIL_HEADER = os.environ.get('GUARDRAIL_HEADER', '{{ guardrail_header }}').strip() or 'x-amz-security-token'
DEBUG = bool(os.environ.get('DEBUG'))
FILTERED_HEADERS = {'x-amzn-trace-id', 'x-forwarded-port', 'x-forwarded-proto', 'host'}

if not LINKED_ASSET_URL or LINKED_ASSET_URL.startswith('{' + '{'):
    print('ERROR: LINKED_ASSET_URL placeholder was not replaced.')
    sys.exit(2)
if not GUARDRAIL_VALUE:
    print('ERROR: GUARDRAIL_VALUE environment variable is not set.')
    sys.exit(2)

if not LINKED_ASSET_URL.startswith(('http://', 'https://')):
    LINKED_ASSET_URL = 'https://' + LINKED_ASSET_URL

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, hdrs):
        raise urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)
    def http_error_302(self, req, fp, code, msg, hdrs):
        raise urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)
    def http_error_303(self, req, fp, code, msg, hdrs):
        raise urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)
    def http_error_307(self, req, fp, code, msg, hdrs):
        raise urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)
    def http_error_308(self, req, fp, code, msg, hdrs):
        raise urllib.error.HTTPError(req.full_url, code, msg, hdrs, fp)

def lambda_handler(event, context):
    if DEBUG:
        print(f'[DEBUG] Full event: {event}')

    method = event['httpMethod']
    path = event['path']
    query_params = (
        event.get('multiValueQueryStringParameters')
        or event.get('queryStringParameters')
    )
    query_string = (
        urllib.parse.urlencode(query_params, doseq=True)
        if query_params else None
    )

    headers = event.get('headers', {})
    body = event.get('body')
    is_base64_encoded = event.get('isBase64Encoded', False)
    stage = event.get('requestContext', {}).get('stage', 'v2')

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

    upstream_url = f"{LINKED_ASSET_URL}{path}" + (f"?{query_string}" if query_string else "")

    if is_base64_encoded and body:
        try:
            body = base64.b64decode(body)
        except Exception:
            print('[!] Failed to decode base64 body.')

    forwarded_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in FILTERED_HEADERS and k.lower() != GUARDRAIL_HEADER.lower()
    }

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

    opener = urllib.request.build_opener(NoRedirectHandler())

    try:
        response = opener.open(request, timeout=10)
        status = response.status
        response_body = response.read()
        response_headers = response.headers
    except urllib.error.HTTPError as error:
        status = error.code
        response_body = error.read()
        response_headers = error.headers
    except urllib.error.URLError as error:
        print(f'[!] Failed to forward request to TS: {str(error)}')
        return {'statusCode': 403}

    try:
        response_text = response_body.decode('utf-8')
        is_text = True
    except UnicodeDecodeError:
        response_text = None
        is_text = False

    if DEBUG:
        debug_body = response_text if is_text else f'<binary: {len(response_body)} bytes>'
        print(f'*** Beacon <- TS ***\nStatus code: {status}\nHeaders: {dict(response_headers)}\nBody: {debug_body}\n')

    if is_text:
        return {
            'statusCode': status,
            'headers': dict(response_headers),
            'body': response_text,
            'isBase64Encoded': False,
        }
    else:
        return {
            'statusCode': status,
            'headers': dict(response_headers),
            'body': base64.b64encode(response_body).decode('utf-8'),
            'isBase64Encoded': True,
        }
