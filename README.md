# lambda_redir

Goal: small Lambda to proxy/redirect C2 HTTP(S) traffic.

Deploy:
- Replace `{{ linked_asset_a_record }}` in `static_lambda.py` at build time (Terraform). This should be the FQDN of your redirector if using one.
- Replace `{{ guardrail_header }}` in `static_lambda.py` at build time (Terraform), or leave it empty to use `x-amz-security-token`.
- Set `GUARDRAIL_VALUE` and optionally `DEBUG=1` as Lambda env vars.
- Deploy `static_lambda.py` behind API Gateway (HTTP API v2).

Runtime:
- Malleable profile must set the configured guardrail header to the same value as `GUARDRAIL_VALUE` on the Lambda.
- Proxy preserves method, query, headers, and body.

That's it.

Reference: https://cypfer.com/trust-me-im-not-malicious-cobalt-strike-redirectors-using-aws-and-azure/
