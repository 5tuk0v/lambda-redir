# lambda_redir

Transparent HTTP(S) proxy for Cobalt Strike C2 traffic through AWS Lambda.

## Setup

1. Replace `{{ linked_asset_a_record }}` with your upstream server (C2, redirector, or other target)
2. Set `GUARDRAIL_VALUE` env var on Lambda (shared secret)
3. Optionally set `GUARDRAIL_HEADER` env var (defaults to `x-amz-security-token`). Can also be configured via Terraform variable `{{ guardrail_header }}`
4. Deploy behind API Gateway (HTTP API v2)
5. Optionally set `DEBUG=1` for request/response logging

## How It Works

- Validates all requests with the guardrail header before forwarding
- Preserves HTTP method, query strings, and body
- Prepends the API Gateway stage to paths (e.g., `/v2/`) before forwarding
- Strips guardrail, AWS infrastructure, and CloudFront headers before forwarding
- Handles both text and binary responses

## Malleable Profile Requirements

**Critical:** All outputs must be base64-encoded. Raw binary data will be corrupted by API Gateway.

**URIs:** All `set uri` directives must include the stage prefix (typically `/v2/`). Example:

```
http-get {
    set uri "/v2/api/fetch";
    ...
}

http-post {
    set uri "/v2/api/telemetry";
    ...
}
```

**Output encoding:** Add `base64;` to all `output` blocks:

```
server {
    output {
        base64;        # Always include this
        prepend "{...}";
        print;
    }
}
```

This ensures data is valid UTF-8 for API Gateway transport.

**Example:** See `mal_profiles/xpn-json-v2.profile` for a known-working Cobalt Strike malleable profile template.

## Notes

- Malleable profile must send the same guardrail header as configured
- C2 server can be private (VPC) or public (opsec choice)
- Tested with Cobalt Strike and a limited profile set. Given the infinite malleable profile options available, adjustments may be needed for other profiles
- Tested with Outflank C2 (OC2). Ensure implants are generated with the correct guardrail header and API Gateway endpoint URL

References: [Cypfer](https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/) • [Scott Taylor](https://scottctaylor12.github.io/lambda-function-urls.html) • [XPN](https://blog.xpnsec.com/aws-lambda-redirector/)