# lambda_redir

Transparent HTTP(S) proxy for C2 traffic through AWS Lambda.

## Setup

1. Replace `{{ linked_asset_a_record }}` with your upstream server (C2, redirector, or other target)
2. Set `GUARDRAIL_VALUE` env var on Lambda (shared secret)
3. Optionally set `GUARDRAIL_HEADER` env var (defaults to `x-amz-security-token`). Can also be configured via Terraform variable `{{ guardrail_header }}`
4. Deploy behind API Gateway (REST API proxy / API Gateway v1). This project was tested with API Gateway REST API (`aws_api_gateway_rest_api`) using a stage named `v2` (so paths are prefixed with `/v2/`).
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
- Upstream server can be private (within a VPC) or public. If the upstream is private, configure the Lambda to access that VPC (attach appropriate subnets and security groups) and ensure networking and IAM are set so the function can reach the upstream host.
- Tested with Cobalt Strike and a limited profile set. Given the infinite malleable profile options available, adjustments may be needed for other profiles
- Tested with Outflank C2 (OC2). Ensure implants are generated with the correct guardrail header and API Gateway endpoint URL

## AI Assistance Disclosure

This project was developed by **5tuk0v** with substantial assistance from AI
coding tools, including **OpenCode** and **OpenAI Codex**, using multiple
models. The exact models and versions used were not consistently recorded.

AI assistance included implementation, debugging, testing, documentation, and
code review. All AI-assisted contributions were directed and reviewed by the
maintainer, who remains responsible for the final result.

References: [Cypfer](https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/) • [Scott Taylor](https://scottctaylor12.github.io/lambda-function-urls.html) • [XPN](https://blog.xpnsec.com/aws-lambda-redirector/)
