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
- Preserves HTTP method, query strings, and body
- Prepends the API Gateway stage to paths (e.g., `/v2/`) before forwarding
- Strips guardrail, AWS infrastructure, and CloudFront headers before forwarding
- Auto-generates correct `Host` header based on upstream URL
- Handles binary responses with base64 encoding

## Notes

- Malleable profile must send the same guardrail header and value as configured
- `DEBUG` env var enables full event/request/response logging
- All requests are validated before forwarding to avoid exposing the C2 server

References: [Cypfer](https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/) • [Scott Taylor](https://scottctaylor12.github.io/lambda-function-urls.html) • [XPN](https://blog.xpnsec.com/aws-lambda-redirector/)