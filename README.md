# lambda_redir

Transparent HTTP(S) proxy for Cobalt Strike C2 traffic through AWS Lambda.

## Deploy

1. Replace `{{ linked_asset_a_record }}` with your C2 server FQDN
2. Set `GUARDRAIL_VALUE` env var on the Lambda (shared secret)
3. Optionally set `GUARDRAIL_HEADER` env var for the header name (defaults to `x-amz-security-token`, or use placeholder `{{ guardrail_header }}`)
4. Deploy behind API Gateway (HTTP API v2)
5. Set `DEBUG=1` env var if you want request/response logging

## How It Works

- Validates all requests with the guardrail header before forwarding
- Preserves HTTP method, query strings, headers, and body
- Prepends `/v2/` to all paths before forwarding
- Strips guardrail and AWS infrastructure headers to avoid leaking redirector details
- Handles binary responses with base64 encoding

## Notes

- Malleable profile must send the same guardrail header and value as configured
- Avoid fixing the `Host` header to a different value; mismatched hosts are rejected by API Gateway/C2
- `DEBUG` takes effect on next Lambda invocation after env var change

References: [Cypfer](https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/) • [Scott Taylor](https://scottctaylor12.github.io/lambda-function-urls.html) • [XPN](https://blog.xpnsec.com/aws-lambda-redirector/)