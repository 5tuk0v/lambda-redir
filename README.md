# lambda_redir

HTTP(S) application proxy for C2 traffic through AWS Lambda.

## Setup

1. Replace `{{ linked_asset_a_record }}` with your upstream server (C2, redirector, or other target)
2. Set `GUARDRAIL_VALUE` env var on Lambda (shared secret)
3. Set `GUARDRAIL_HEADER`, or ensure the deployment replaces `{{ guardrail_header }}`. Use `x-amz-security-token` when no custom header is required
4. Deploy behind API Gateway REST API (proxy integration / payload v1). The tested configuration uses a stage named `v2`
5. Optionally set `DEBUG=1` for verbose test logging. This logs headers and payloads and should not be enabled in normal operation. Unset `DEBUG` to disable it

## How It Works

- Validates all requests with the guardrail header before forwarding
- Forwards the HTTP method, query parameters (including repeated values), headers, and body
- Prepends the API Gateway stage to paths (e.g., `/v2/`) before forwarding
- Removes the guardrail and selected infrastructure headers before forwarding
- Handles both text and binary responses

## Malleable Profile Requirements

Use text-safe `base64` or `base64url` transforms for profile output. Raw binary output requires compatible API Gateway binary-media configuration and explicit testing.

**URIs:** Include the API Gateway stage prefix in client-facing URIs when required by the deployed endpoint. The Lambda adds the detected stage to the upstream path when it is absent. Example for the tested `v2` stage:

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

**Output encoding:** Use a text-safe base64-family transform in output blocks:

```
server {
    output {
        base64;
        prepend "{...}";
        print;
    }
}
```

This keeps profile output text-safe for API Gateway transport.

**Example:** See `mal_profiles/xpn-json-v2.profile` for a known-working Cobalt Strike malleable profile template.

## Notes

- Malleable profile must send the same guardrail header as configured
- Upstream server can be private (within a VPC) or public. If the upstream is private, configure the Lambda to access that VPC (attach appropriate subnets and security groups) and ensure networking and IAM are set so the function can reach the upstream host.
- Tested with Cobalt Strike and a limited profile set. Profiles that depend on duplicate headers, exact header ordering, or exact wire representation require additional testing
- Tested with Outflank C2 (OC2). Ensure implants are generated with the correct guardrail header and API Gateway endpoint URL

## AI Assistance Disclosure

This project was developed by **5tuk0v** with substantial assistance from AI
coding tools, including **OpenCode** and **OpenAI Codex**, using multiple
models. The exact models and versions used were not consistently recorded.

AI assistance included implementation, debugging, testing, documentation, and
code review. All AI-assisted contributions were directed and reviewed by the
maintainer, who remains responsible for the final result.

References: [Cypfer](https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/) • [Scott Taylor](https://scottctaylor12.github.io/lambda-function-urls.html) • [XPN](https://blog.xpnsec.com/aws-lambda-redirector/)
