# lambda_redir

Goal: small Lambda to proxy/redirect C2 HTTP(S) traffic.

Deploy:
- Replace `{{ linked_asset_a_record }}` in `static_lambda.py` at build time (Terraform). This should be the FQDN of your redirector if using one.
- Replace `{{ guardrail_header }}` in `static_lambda.py` at build time (Terraform), or leave it empty to use `x-amz-security-token`.
- Set `GUARDRAIL_VALUE` as a Lambda env var, and set `DEBUG` only when you want request and response debug logs.
- Deploy `static_lambda.py` behind API Gateway (HTTP API v2).

Runtime:
- Malleable profile must set the configured guardrail header to the same value as `GUARDRAIL_VALUE` on the Lambda.
- `DEBUG` is read inside the handler, so toggling the Lambda env var takes effect on the next invocation that lands on a fresh execution environment.
- Proxy preserves method, query, headers, and body.
- Avoid fixing the `Host` header to a different address than the public endpoint being contacted; a mismatched `Host` can be rejected before the request ever reaches API Gateway or Lambda.

That's it.

Reference: https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/
