import base64
import contextlib
import importlib
import io
import os
import sys
import unittest
import urllib.error
from unittest.mock import Mock, patch


def load_handler_module():
    """Import the template safely, then configure it for offline tests."""
    sys.modules.pop('lambda_redir', None)
    with patch.dict(os.environ, {}, clear=True), \
            patch.object(sys, 'exit'), \
            contextlib.redirect_stdout(io.StringIO()):
        module = importlib.import_module('lambda_redir')

    module.LINKED_ASSET_URL = 'https://upstream.example.test'
    module.GUARDRAIL_VALUE = 'fixture-guardrail'
    module.GUARDRAIL_HEADER = 'x-amz-security-token'
    module.DEBUG = False
    return module


handler = load_handler_module()


class FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self):
        return self._body


def gateway_event(method, path, headers=None, query=None, multi_query=None,
                  body=None, is_base64_encoded=False):
    return {
        'httpMethod': method,
        'path': path,
        'headers': headers or {},
        'queryStringParameters': query,
        'multiValueQueryStringParameters': multi_query,
        'body': body,
        'isBase64Encoded': is_base64_encoded,
        'requestContext': {'stage': 'v2'},
    }


def valid_headers(**extra):
    headers = {
        'Accept': '*/*',
        'Cache-Control': 'no-cache',
        'Host': 'gateway.example.test',
        'User-Agent': 'Mozilla/5.0 fixture',
        'x-amz-security-token': 'fixture-guardrail',
        'X-Amzn-Trace-Id': 'Root=fixture',
        'X-Forwarded-Port': '443',
        'X-Forwarded-Proto': 'https',
    }
    headers.update(extra)
    return headers


class LambdaRedirRegressionTests(unittest.TestCase):
    def call_handler(self, event, response):
        opener = Mock()
        opener.open.return_value = response
        with patch.object(handler.urllib.request, 'build_opener', return_value=opener):
            result = handler.lambda_handler(event, None)
        return result, opener

    def test_rejects_missing_guardrail_before_creating_an_upstream_request(self):
        event = gateway_event('GET', '/api/fetch', headers={'User-Agent': 'fixture'})

        with patch.object(handler.urllib.request, 'build_opener') as build_opener:
            result = handler.lambda_handler(event, None)

        self.assertEqual(result, {'statusCode': 403, 'body': 'Forbidden'})
        build_opener.assert_not_called()

    def test_xpn_style_empty_get_poll_is_forwarded(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(**{'CloudFront-Viewer-Country': 'CA'}),
            query={'token': 'fixture-metadata-token'},
        )
        upstream_body = b'{"version":"2","count":"1","data":""}'

        result, opener = self.call_handler(
            event,
            FakeResponse(200, upstream_body, {'Content-Type': 'application/json'}),
        )

        request = opener.open.call_args.args[0]
        forwarded_headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(
            request.full_url,
            'https://upstream.example.test/v2/api/fetch?token=fixture-metadata-token',
        )
        self.assertEqual(request.get_method(), 'GET')
        self.assertIsNone(request.data)
        self.assertNotIn('x-amz-security-token', forwarded_headers)
        self.assertNotIn('host', forwarded_headers)
        self.assertNotIn('x-amzn-trace-id', forwarded_headers)
        self.assertEqual(forwarded_headers['cloudfront-viewer-country'], 'CA')
        self.assertEqual(result, {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': upstream_body.decode('utf-8'),
            'isBase64Encoded': False,
        })

    def test_xpn_style_post_preserves_query_and_json_result_body(self):
        report = 'fixture-short-report'
        body = f'{{"version":"2","report":"{report}"}}'
        event = gateway_event(
            'POST',
            '/api/telemetry',
            headers=valid_headers(**{'Content-Type': 'application/json; charset=utf-8'}),
            query={'action': 'GetExtensibilityContext', 'token': '472485524'},
            body=body,
        )

        result, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(
            request.full_url,
            'https://upstream.example.test/v2/api/telemetry?'
            'action=GetExtensibilityContext&token=472485524',
        )
        self.assertEqual(request.data, body.encode('utf-8'))
        self.assertEqual(result['statusCode'], 200)
        self.assertFalse(result['isBase64Encoded'])

    def test_duplicate_query_parameters_are_forwarded_without_data_loss(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(),
            query={'id': 'second'},
            multi_query={'id': ['first', 'second'], 'mode': ['full']},
        )

        _, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        request = opener.open.call_args.args[0]
        self.assertEqual(
            request.full_url,
            'https://upstream.example.test/v2/api/fetch?'
            'id=first&id=second&mode=full',
        )

    def test_large_post_result_is_not_truncated(self):
        report = 'A' * 48000
        body = f'{{"version":"2","report":"{report}"}}'
        event = gateway_event(
            'POST',
            '/api/telemetry',
            headers=valid_headers(**{'Content-Type': 'application/json; charset=utf-8'}),
            query={'action': 'GetExtensibilityContext', 'token': '472485524'},
            body=body,
        )

        _, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        request = opener.open.call_args.args[0]
        self.assertEqual(len(request.data), len(body.encode('utf-8')))
        self.assertEqual(request.data, body.encode('utf-8'))

    def test_base64_encoded_request_body_is_decoded_before_forwarding(self):
        original_body = b'\x00\xfffixture-binary-body'
        event = gateway_event(
            'POST',
            '/api/telemetry',
            headers=valid_headers(),
            body=base64.b64encode(original_body).decode('ascii'),
            is_base64_encoded=True,
        )

        _, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        self.assertEqual(opener.open.call_args.args[0].data, original_body)

    def test_binary_upstream_response_uses_lambda_base64_envelope(self):
        upstream_body = b'\x00\xfffixture-binary-response'
        event = gateway_event('GET', '/api/fetch', headers=valid_headers())

        result, _ = self.call_handler(
            event,
            FakeResponse(200, upstream_body, {'Content-Type': 'application/octet-stream'}),
        )

        self.assertEqual(result['statusCode'], 200)
        self.assertTrue(result['isBase64Encoded'])
        self.assertEqual(base64.b64decode(result['body']), upstream_body)

    def test_upstream_http_error_is_returned_to_the_client(self):
        event = gateway_event('GET', '/api/fetch', headers=valid_headers())
        opener = Mock()
        error = urllib.error.HTTPError(
            'https://upstream.example.test/v2/api/fetch',
            404,
            'Not Found',
            {'Content-Type': 'text/plain'},
            io.BytesIO(b'not found'),
        )
        opener.open.side_effect = error

        with patch.object(handler.urllib.request, 'build_opener', return_value=opener):
            result = handler.lambda_handler(event, None)

        self.assertEqual(result, {
            'statusCode': 404,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'not found',
            'isBase64Encoded': False,
        })


if __name__ == '__main__':
    unittest.main()
