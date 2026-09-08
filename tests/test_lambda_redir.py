import base64
import contextlib
import email.message
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


def gateway_event(method, path, headers=None, multi_headers=None, query=None,
                  multi_query=None, body=None, is_base64_encoded=False,
                  stage='v2'):
    return {
        'httpMethod': method,
        'path': path,
        'headers': headers or {},
        'multiValueHeaders': multi_headers,
        'queryStringParameters': query,
        'multiValueQueryStringParameters': multi_query,
        'body': body,
        'isBase64Encoded': is_base64_encoded,
        'requestContext': {'stage': stage},
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

    def test_rejects_incorrect_guardrail_before_upstream_request(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers={'x-amz-security-token': 'incorrect'},
        )

        with patch.object(handler.urllib.request, 'build_opener') as build_opener:
            result = handler.lambda_handler(event, None)

        self.assertEqual(result, {'statusCode': 403, 'body': 'Forbidden'})
        build_opener.assert_not_called()

    def test_guardrail_header_name_is_case_insensitive(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(**{
                'x-amz-security-token': 'replaced-below',
            }),
        )
        event['headers'].pop('x-amz-security-token')
        event['headers']['X-AmZ-SeCuRiTy-ToKeN'] = 'fixture-guardrail'

        result, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(opener.open.call_count, 1)

    def test_rejects_ambiguous_multi_value_guardrail(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(),
            multi_headers={
                'x-amz-security-token': [
                    'fixture-guardrail',
                    'conflicting-value',
                ],
            },
        )

        with patch.object(handler.urllib.request, 'build_opener') as build_opener:
            result = handler.lambda_handler(event, None)

        self.assertEqual(result, {'statusCode': 403, 'body': 'Forbidden'})
        build_opener.assert_not_called()

    def test_accepts_one_multi_value_guardrail(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(),
            multi_headers={
                'X-AmZ-SeCuRiTy-ToKeN': ['fixture-guardrail'],
            },
        )

        result, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(opener.open.call_count, 1)

    def test_rejects_identical_duplicate_guardrail_values(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(),
            multi_headers={
                'x-amz-security-token': [
                    'fixture-guardrail',
                    'fixture-guardrail',
                ],
            },
        )

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

    def test_stage_is_added_to_an_unprefixed_path(self):
        event = gateway_event('GET', '/api/fetch', headers=valid_headers())

        _, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        request = opener.open.call_args.args[0]
        self.assertEqual(
            request.full_url,
            'https://upstream.example.test/v2/api/fetch',
        )

    def test_existing_stage_prefix_is_not_added_twice(self):
        event = gateway_event('GET', '/v2/api/fetch', headers=valid_headers())

        _, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        request = opener.open.call_args.args[0]
        self.assertEqual(
            request.full_url,
            'https://upstream.example.test/v2/api/fetch',
        )

    def test_event_stage_is_used_instead_of_the_v2_fallback(self):
        event = gateway_event(
            'GET',
            '/api/fetch',
            headers=valid_headers(),
            stage='canary',
        )

        _, opener = self.call_handler(
            event,
            FakeResponse(200, b'{"version":"2","count":"1","data":""}'),
        )

        request = opener.open.call_args.args[0]
        self.assertEqual(
            request.full_url,
            'https://upstream.example.test/canary/api/fetch',
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

    @unittest.expectedFailure
    def test_repeated_response_headers_use_multi_value_envelope(self):
        response_headers = email.message.Message()
        response_headers['Content-Type'] = 'text/plain'
        response_headers['Set-Cookie'] = 'first=value1; Path=/'
        response_headers['Set-Cookie'] = 'second=value2; Path=/'
        event = gateway_event('GET', '/api/fetch', headers=valid_headers())

        result, _ = self.call_handler(
            event,
            FakeResponse(200, b'ok', response_headers),
        )

        self.assertEqual(result['headers'], {'Content-Type': 'text/plain'})
        self.assertEqual(result['multiValueHeaders'], {
            'Set-Cookie': [
                'first=value1; Path=/',
                'second=value2; Path=/',
            ],
        })

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

    def test_redirect_responses_are_returned_without_following(self):
        for status in (301, 302, 303, 307):
            with self.subTest(status=status):
                redirect_handler = handler.NoRedirectHandler()
                redirect_method = getattr(
                    redirect_handler,
                    f'http_error_{status}',
                )
                with self.assertRaises(urllib.error.HTTPError):
                    redirect_method(
                        Mock(full_url=(
                            'https://upstream.example.test/v2/api/fetch'
                        )),
                        io.BytesIO(b''),
                        status,
                        'Redirect',
                        {'Location': 'https://elsewhere.example.test/'},
                    )

                event = gateway_event('GET', '/api/fetch', headers=valid_headers())
                opener = Mock()
                opener.open.side_effect = urllib.error.HTTPError(
                    'https://upstream.example.test/v2/api/fetch',
                    status,
                    'Redirect',
                    {'Location': 'https://elsewhere.example.test/'},
                    io.BytesIO(b''),
                )

                with patch.object(
                        handler.urllib.request,
                        'build_opener',
                        return_value=opener):
                    result = handler.lambda_handler(event, None)

                self.assertEqual(result['statusCode'], status)
                self.assertEqual(
                    result['headers']['Location'],
                    'https://elsewhere.example.test/',
                )
                self.assertEqual(opener.open.call_count, 1)

    def test_308_redirect_is_not_followed(self):
        redirect_handler = handler.NoRedirectHandler()
        request = Mock(full_url='https://upstream.example.test/v2/api/fetch')

        with self.assertRaises(urllib.error.HTTPError) as raised:
            redirect_handler.http_error_308(
                request,
                io.BytesIO(b''),
                308,
                'Permanent Redirect',
                {'Location': 'https://elsewhere.example.test/'},
            )

        self.assertEqual(raised.exception.code, 308)

    def test_upstream_network_errors_keep_the_legacy_403_response(self):
        failures = {
            'connection refused': ConnectionRefusedError('fixture refused'),
            'dns failure': OSError('fixture name resolution failed'),
            'tls failure': OSError('fixture certificate rejected'),
            'timeout': TimeoutError('fixture timed out'),
        }

        for name, reason in failures.items():
            with self.subTest(failure=name):
                event = gateway_event('GET', '/api/fetch', headers=valid_headers())
                opener = Mock()
                opener.open.side_effect = urllib.error.URLError(reason)

                with patch.object(
                        handler.urllib.request,
                        'build_opener',
                        return_value=opener):
                    result = handler.lambda_handler(event, None)

                self.assertEqual(result, {'statusCode': 403})


if __name__ == '__main__':
    unittest.main()
