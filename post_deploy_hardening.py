#!/usr/bin/env python3
"""
Post-deployment hardening for an AWS Lambda -> NGINX proxy stack.

Goal A (always): set GUARDRAIL_VALUE on Lambda + attach IP allowlist resource policy to API GW.
Goal B (--vpc-hardening): VPC-attach Lambda + restrict NGINX inbound to Lambda SG only.
Cleanup (--cleanup-vpc-hardening): remove Goal B dependencies before Terraform destroy.

Run after the infrastructure deployment completes. Re-run Goal B after any
redeployment that restores the original security-group rules.
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.parse


def run(args, check=True, capture_output=True):
    try:
        r = subprocess.run(args, check=check, capture_output=capture_output, text=True)
        return r.stdout.strip() if capture_output else None
    except subprocess.CalledProcessError as e:
        print(f'[!] Command failed: {" ".join(args)}')
        if e.stderr:
            print(f'    {e.stderr.strip()}')
        sys.exit(1)


def aws_json(*args):
    return json.loads(run(['aws', *args]))


def aws_run(*args, check=True):
    run(['aws', *args], check=check, capture_output=True)


def aws_run_with_retry(*args, timeout=120, interval=5):
    """Retry AWS operations affected by IAM or Lambda update propagation."""
    retryable_errors = (
        'does not have permissions to call CreateNetworkInterface',
        'ResourceConflictException',
        'An update is in progress',
    )
    command = ['aws', *args]
    deadline = time.monotonic() + timeout

    while True:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()

        error = result.stderr.strip()
        retryable = any(fragment in error for fragment in retryable_errors)
        remaining = deadline - time.monotonic()
        if not retryable or remaining <= 0:
            print(f'[!] Command failed: {" ".join(command)}')
            if error:
                print(f'    {error}')
            sys.exit(1)

        delay = min(interval, remaining)
        print(f'    AWS propagation pending; retrying in {delay:g}s...')
        time.sleep(delay)


def fail(message):
    print(f'[!] {message}')
    sys.exit(1)


def find_lambda_security_group(args):
    # AWS reserves names beginning with "sg-" for security group IDs.
    group_name = f'lambda-redir-{args.api_id}'
    result = aws_json('ec2', 'describe-security-groups',
                      '--region', args.region,
                      '--filters',
                      f'Name=group-name,Values={group_name}',
                      f'Name=vpc-id,Values={args.vpc_id}')
    groups = result.get('SecurityGroups', [])
    if len(groups) > 1:
        fail(f'Multiple security groups named {group_name} found in VPC {args.vpc_id}.')
    return groups[0] if groups else None


def nginx_references_lambda_sg(nginx_sg, lambda_sg_id, port):
    for permission in nginx_sg.get('IpPermissions', []):
        if permission.get('IpProtocol') != 'tcp':
            continue
        if permission.get('FromPort') != port or permission.get('ToPort') != port:
            continue
        if any(pair.get('GroupId') == lambda_sg_id
               for pair in permission.get('UserIdGroupPairs', [])):
            return True
    return False


def lambda_vpc_access_policy():
    return {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Action': [
                'ec2:CreateNetworkInterface',
                'ec2:DescribeNetworkInterfaces',
                'ec2:DeleteNetworkInterface',
                'ec2:DescribeSubnets',
                'ec2:DescribeSecurityGroups',
                'ec2:DescribeVpcs',
            ],
            'Resource': '*',
        }],
    }


def normalize_policy_document(document):
    """Return an IAM policy as a dict whether AWS returned JSON or URL encoding."""
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            return json.loads(urllib.parse.unquote(document))
        except json.JSONDecodeError:
            return None
    return None


def wait_for_lambda_enis(args, lambda_sg_id):
    deadline = time.monotonic() + args.cleanup_timeout
    while True:
        result = aws_json('ec2', 'describe-network-interfaces',
                          '--region', args.region,
                          '--filters', f'Name=group-id,Values={lambda_sg_id}')
        eni_ids = [eni['NetworkInterfaceId'] for eni in result.get('NetworkInterfaces', [])]
        if not eni_ids:
            print('    Lambda ENIs removed.')
            return

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail(f'Timed out waiting for Lambda ENIs to disappear: {eni_ids}')

        print(f'    Waiting for Lambda ENIs: {eni_ids}')
        time.sleep(min(15, remaining))


def cleanup_vpc_hardening(args):
    print('\n--- Cleanup: Goal B VPC hardening ---')

    print(f'[*] Inspecting Lambda configuration: {args.function_name}')
    config = aws_json('lambda', 'get-function-configuration',
                      '--function-name', args.function_name,
                      '--region', args.region)
    if config.get('LastUpdateStatus') == 'InProgress':
        print('    Lambda update in progress; waiting...')
        aws_run('lambda', 'wait', 'function-updated-v2',
                '--function-name', args.function_name,
                '--region', args.region)
        config = aws_json('lambda', 'get-function-configuration',
                          '--function-name', args.function_name,
                          '--region', args.region)
    if config.get('LastUpdateStatus') == 'Failed':
        fail('Lambda LastUpdateStatus is Failed. Resolve it before cleanup.')

    role_name = config['Role'].split('/')[-1]
    vpc_config = config.get('VpcConfig', {})
    attached_sgs = vpc_config.get('SecurityGroupIds', [])

    print(f'[*] Finding Goal B Lambda security group in VPC {args.vpc_id}...')
    lambda_sg = find_lambda_security_group(args)
    lambda_sg_id = lambda_sg['GroupId'] if lambda_sg else None

    if not lambda_sg_id and attached_sgs:
        fail(f'Lambda is attached to unrecognized security groups: {attached_sgs}')
    if lambda_sg_id and attached_sgs and attached_sgs != [lambda_sg_id]:
        fail(f'Lambda VPC security groups do not match Goal B: {attached_sgs}')

    if lambda_sg_id:
        print(f'    Lambda SG: {lambda_sg_id}')
        nginx_result = aws_json('ec2', 'describe-security-groups',
                                '--region', args.region,
                                '--group-ids', args.nginx_sg_id)
        nginx_groups = nginx_result.get('SecurityGroups', [])
        if len(nginx_groups) != 1:
            fail(f'Could not uniquely resolve NGINX SG {args.nginx_sg_id}.')
        nginx_sg = nginx_groups[0]
        if nginx_sg.get('VpcId') != args.vpc_id:
            fail(f'NGINX SG {args.nginx_sg_id} is not in VPC {args.vpc_id}.')

        for port in [80, 443]:
            if nginx_references_lambda_sg(nginx_sg, lambda_sg_id, port):
                print(f'[*] Removing NGINX TCP/{port} ingress reference to {lambda_sg_id}...')
                aws_run('ec2', 'revoke-security-group-ingress',
                        '--region', args.region,
                        '--group-id', args.nginx_sg_id,
                        '--protocol', 'tcp', '--port', str(port),
                        '--source-group', lambda_sg_id)
                print('    Removed.')
            else:
                print(f'[*] NGINX TCP/{port} ingress reference already absent.')
    else:
        print('    Goal B Lambda SG already absent.')

    if lambda_sg_id and attached_sgs == [lambda_sg_id]:
        print(f'[*] Detaching Lambda from VPC: {args.function_name}...')
        aws_run('lambda', 'update-function-configuration',
                '--function-name', args.function_name,
                '--region', args.region,
                '--vpc-config', json.dumps({
                    'SubnetIds': [],
                    'SecurityGroupIds': [],
                }))
        aws_run('lambda', 'wait', 'function-updated-v2',
                '--function-name', args.function_name,
                '--region', args.region)
        print('    Lambda detached.')
    elif not attached_sgs:
        print('[*] Lambda already detached from VPC.')

    if lambda_sg_id:
        print(f'[*] Waiting for ENIs associated with {lambda_sg_id}...')
        wait_for_lambda_enis(args, lambda_sg_id)
        print(f'[*] Deleting Lambda security group {lambda_sg_id}...')
        aws_run('ec2', 'delete-security-group',
                '--region', args.region,
                '--group-id', lambda_sg_id)
        print('    Deleted.')

    print(f'[*] Checking inline IAM policy on role {role_name}...')
    policies = aws_json('iam', 'list-role-policies', '--role-name', role_name)
    if 'LambdaVPCAccess' in policies.get('PolicyNames', []):
        policy = aws_json('iam', 'get-role-policy',
                          '--role-name', role_name,
                          '--policy-name', 'LambdaVPCAccess')
        policy_document = normalize_policy_document(policy.get('PolicyDocument'))
        if policy_document != lambda_vpc_access_policy():
            fail('LambdaVPCAccess exists but was not created by Goal B; refusing to delete it.')
        aws_run('iam', 'delete-role-policy',
                '--role-name', role_name,
                '--policy-name', 'LambdaVPCAccess')
        print('    LambdaVPCAccess deleted.')
    else:
        print('    LambdaVPCAccess already absent.')

    print('\n[+] Goal B cleanup done. Terraform destroy can now be started.')


def main():
    examples = """Examples:
  Goal A only:
    python post_deploy_hardening.py --function-name FUNCTION --api-id API_ID --region REGION --guardrail-secret VALUE --allowed-ip 203.0.113.10/32

  Goal A and Goal B:
    python post_deploy_hardening.py --function-name FUNCTION --api-id API_ID --region REGION --guardrail-secret VALUE --allowed-ip 203.0.113.10/32 --vpc-hardening --vpc-id VPC_ID --subnet-id SUBNET_ID --nginx-sg-id NGINX_SG_ID

  Add --nginx-instance-id, --nginx-hosted-zone-id, and --nginx-fqdn when the
  NGINX DNS record must be changed to its private address.

  Remove Goal B resources before infrastructure teardown:
    python post_deploy_hardening.py --function-name FUNCTION --api-id API_ID --region REGION --cleanup-vpc-hardening --vpc-id VPC_ID --nginx-sg-id NGINX_SG_ID

Goal A updates the Lambda guardrail settings and API Gateway source-IP policy.
Goal B additionally attaches Lambda to a VPC and restricts traffic between the
Lambda and NGINX security groups. Cleanup removes only Goal B dependencies.
"""
    p = argparse.ArgumentParser(
        description='Apply post-deployment hardening to Lambda and API Gateway',
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--function-name', required=True, help='Lambda function name')
    p.add_argument('--api-id', required=True, help='API Gateway REST API ID')
    p.add_argument('--stage', default='v2', help='API Gateway stage name (default: v2)')
    p.add_argument('--guardrail-secret', help='Value assigned to the Lambda GUARDRAIL_VALUE variable')
    p.add_argument('--guardrail-header', default='x-amz-security-token', help='GUARDRAIL_HEADER (default: x-amz-security-token)')
    p.add_argument('--allowed-ip', action='append', dest='allowed_ips', metavar='IP/CIDR',
                   help='Allowed source IP/CIDR for API GW (repeat for multiple: --allowed-ip 1.2.3.4/32 --allowed-ip 5.6.7.8/32)')
    p.add_argument('--region', required=True, help='AWS region containing the deployment')
    p.add_argument('--debug-lambda', action='store_true', help='Set DEBUG=1 on Lambda (verbose CloudWatch logs)')

    b = p.add_argument_group('Goal B: optional VPC hardening')
    mode = b.add_mutually_exclusive_group()
    mode.add_argument('--vpc-hardening', action='store_true',
                      help='Apply Goal B after Goal A')
    mode.add_argument('--cleanup-vpc-hardening', action='store_true',
                      help='Remove Goal B dependencies before Terraform destroy')
    b.add_argument('--vpc-id', help='VPC containing Lambda and NGINX')
    b.add_argument('--subnet-id', help='Subnet used by Lambda to reach NGINX')
    b.add_argument('--nginx-sg-id', help='NGINX security group ID')
    b.add_argument('--nginx-instance-id', help='NGINX EC2 instance ID (for DNS private IP update)')
    b.add_argument('--nginx-hosted-zone-id', help='Route53 hosted zone ID for NGINX DNS record')
    b.add_argument('--nginx-fqdn', help='NGINX FQDN to update DNS A record to private IP')
    b.add_argument('--cleanup-timeout', type=int, default=1500, metavar='SECONDS',
                   help='Maximum ENI cleanup wait (default: 1500)')

    args = p.parse_args()

    if args.cleanup_vpc_hardening:
        for field, flag in [('vpc_id', '--vpc-id'), ('nginx_sg_id', '--nginx-sg-id')]:
            if not getattr(args, field):
                p.error(f'--cleanup-vpc-hardening requires {flag}')
        if args.cleanup_timeout <= 0:
            p.error('--cleanup-timeout must be greater than zero')
    else:
        if not args.guardrail_secret:
            p.error('--guardrail-secret is required unless --cleanup-vpc-hardening is used')
        if not args.allowed_ips:
            p.error('--allowed-ip is required unless --cleanup-vpc-hardening is used')

    if args.vpc_hardening:
        for field, flag in [('vpc_id', '--vpc-id'), ('subnet_id', '--subnet-id'), ('nginx_sg_id', '--nginx-sg-id')]:
            if not getattr(args, field):
                p.error(f'--vpc-hardening requires {flag}')

    # --- Resolve account ID ---
    print('[*] Resolving AWS identity...')
    identity = aws_json('sts', 'get-caller-identity')
    account_id = identity['Account']
    print(f'    Account: {account_id}  Region: {args.region}')

    if args.cleanup_vpc_hardening:
        cleanup_vpc_hardening(args)
        return

    # -----------------------------------------------------------------------
    # GOAL A: Lambda env vars
    # -----------------------------------------------------------------------
    print(f'\n[*] Updating Lambda env vars: {args.function_name}')
    config = aws_json('lambda', 'get-function-configuration',
                      '--function-name', args.function_name,
                      '--region', args.region)
    existing_env = config.get('Environment', {}).get('Variables', {})

    new_env = dict(existing_env)
    new_env['GUARDRAIL_VALUE'] = args.guardrail_secret
    if args.guardrail_header != 'x-amz-security-token':
        new_env['GUARDRAIL_HEADER'] = args.guardrail_header
    if args.debug_lambda:
        new_env['DEBUG'] = '1'
    elif 'DEBUG' in new_env:
        del new_env['DEBUG']

    aws_run('lambda', 'update-function-configuration',
            '--function-name', args.function_name,
            '--region', args.region,
            '--environment', json.dumps({'Variables': new_env}))
    print('    Done.')

    # -----------------------------------------------------------------------
    # GOAL A: API Gateway resource policy
    # -----------------------------------------------------------------------
    arn_base = f'arn:aws:execute-api:{args.region}:{account_id}:{args.api_id}/*'
    source_ips = args.allowed_ips if len(args.allowed_ips) > 1 else args.allowed_ips[0]

    policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'AllowInvoke',
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 'execute-api:Invoke',
                'Resource': arn_base,
            },
            {
                'Sid': 'DenyNotFromAllowedIPs',
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 'execute-api:Invoke',
                'Resource': arn_base,
                'Condition': {
                    'NotIpAddress': {
                        'aws:SourceIp': source_ips,
                    }
                },
            },
        ],
    }

    # API Gateway expects the policy as a JSON string inside the patch
    # operation. Passing URL-encoded JSON (%7B%22...) produces an invalid
    # policy document.
    policy_patch = json.dumps([{
        'op': 'replace',
        'path': '/policy',
        'value': json.dumps(policy, separators=(',', ':')),
    }])

    print(f'\n[*] Attaching API GW resource policy (allowed: {args.allowed_ips})...')
    aws_run('apigateway', 'update-rest-api',
            '--rest-api-id', args.api_id,
            '--region', args.region,
            '--patch-operations', policy_patch)
    print('    Policy attached.')

    print(f'\n[*] Redeploying stage "{args.stage}"...')
    aws_run('apigateway', 'create-deployment',
            '--rest-api-id', args.api_id,
            '--region', args.region,
            '--stage-name', args.stage)
    print('    Redeployed.')

    if not args.vpc_hardening:
        print('\n[+] Goal A done. NGINX still exposed 0.0.0.0/0.')
        print('    Run with --vpc-hardening to lock NGINX down to Lambda SG only.')
        return

    # -----------------------------------------------------------------------
    # GOAL B: VPC hardening
    # -----------------------------------------------------------------------
    print('\n--- Goal B: VPC hardening ---')

    # 1. Add EC2 VPC permissions to Lambda execution role
    print('[*] Adding EC2 VPC perms to Lambda execution role...')
    role_name = config['Role'].split('/')[-1]
    ec2_policy = lambda_vpc_access_policy()
    aws_run('iam', 'put-role-policy',
            '--role-name', role_name,
            '--policy-name', 'LambdaVPCAccess',
            '--policy-document', json.dumps(ec2_policy))
    print(f'    Role: {role_name}  Policy: LambdaVPCAccess')

    # 2. Create dedicated Lambda security group
    print(f'\n[*] Creating Lambda security group in VPC {args.vpc_id}...')
    sg_out = aws_json('ec2', 'create-security-group',
                      '--region', args.region,
                      '--group-name', f'lambda-redir-{args.api_id}',
                      '--description', f'Lambda redirector outbound - API {args.api_id}',
                      '--vpc-id', args.vpc_id)
    lambda_sg_id = sg_out['GroupId']
    print(f'    Lambda SG: {lambda_sg_id}')

    # Replace the default egress rule before adding the narrow NGINX rules.
    print('    Removing default outbound access...')
    aws_run('ec2', 'revoke-security-group-egress',
            '--region', args.region,
            '--group-id', lambda_sg_id,
            '--protocol', '-1', '--cidr', '0.0.0.0/0')
    aws_run('ec2', 'revoke-security-group-egress',
            '--region', args.region,
            '--group-id', lambda_sg_id,
            '--protocol', '-1', '--cidr', '::/0',
            check=False)

    lambda_egress = [{
        'IpProtocol': 'tcp',
        'FromPort': port,
        'ToPort': port,
        'UserIdGroupPairs': [{
            'GroupId': args.nginx_sg_id,
            'Description': f'{label} to NGINX',
        }],
    } for port, label in [(80, 'HTTP'), (443, 'HTTPS')]]
    aws_run('ec2', 'authorize-security-group-egress',
            '--region', args.region,
            '--group-id', lambda_sg_id,
            '--ip-permissions', json.dumps(lambda_egress))
    print('    Lambda outbound: HTTP/HTTPS to NGINX SG only.')

    # 3. Attach Lambda to VPC
    print(f'\n[*] Attaching Lambda to VPC (subnet: {args.subnet_id}, SG: {lambda_sg_id})...')
    aws_run_with_retry('lambda', 'update-function-configuration',
                       '--function-name', args.function_name,
                       '--region', args.region,
                       '--vpc-config', json.dumps({
                           'SubnetIds': [args.subnet_id],
                           'SecurityGroupIds': [lambda_sg_id],
                       }))
    print('    VPC update accepted; waiting for Lambda to finish...')
    aws_run('lambda', 'wait', 'function-updated-v2',
            '--function-name', args.function_name,
            '--region', args.region)
    updated_config = aws_json('lambda', 'get-function-configuration',
                              '--function-name', args.function_name,
                              '--region', args.region)
    updated_vpc = updated_config.get('VpcConfig', {})
    if (updated_config.get('LastUpdateStatus') != 'Successful'
            or updated_vpc.get('SecurityGroupIds') != [lambda_sg_id]
            or updated_vpc.get('SubnetIds') != [args.subnet_id]):
        fail('Lambda VPC update did not finish with the expected subnet and security group. '
             f'Status={updated_config.get("LastUpdateStatus")}, VpcConfig={updated_vpc}')
    print('    Done. Lambda now in VPC.')

    # 4. Restrict NGINX inbound: revoke 0.0.0.0/0, allow Lambda SG only
    print(f'\n[*] Restricting NGINX SG {args.nginx_sg_id} inbound to Lambda SG only...')
    for port in ['80', '443']:
        aws_run('ec2', 'revoke-security-group-ingress',
                '--region', args.region,
                '--group-id', args.nginx_sg_id,
                '--protocol', 'tcp', '--port', port,
                '--cidr', '0.0.0.0/0',
                check=False)
    nginx_ingress = [{
        'IpProtocol': 'tcp',
        'FromPort': port,
        'ToPort': port,
        'UserIdGroupPairs': [{
            'GroupId': lambda_sg_id,
            'Description': f'{label} from Lambda',
        }],
    } for port, label in [(80, 'HTTP'), (443, 'HTTPS')]]
    aws_run('ec2', 'authorize-security-group-ingress',
            '--region', args.region,
            '--group-id', args.nginx_sg_id,
            '--ip-permissions', json.dumps(nginx_ingress))
    print('    NGINX inbound: HTTP/HTTPS from Lambda SG only.')

    # 5. Update NGINX DNS A record to private IP
    if args.nginx_instance_id and args.nginx_hosted_zone_id and args.nginx_fqdn:
        print(f'\n[*] Updating NGINX DNS to private IP (instance: {args.nginx_instance_id})...')
        ec2_info = aws_json('ec2', 'describe-instances',
                            '--region', args.region,
                            '--instance-ids', args.nginx_instance_id)
        private_ip = ec2_info['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        change_batch = {
            'Comment': 'NGINX private IP for Lambda VPC routing',
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': args.nginx_fqdn,
                    'Type': 'A',
                    'TTL': 60,
                    'ResourceRecords': [{'Value': private_ip}],
                },
            }],
        }
        aws_run('route53', 'change-resource-record-sets',
                '--hosted-zone-id', args.nginx_hosted_zone_id,
                '--change-batch', json.dumps(change_batch))
        print(f'    DNS: {args.nginx_fqdn} -> {private_ip} (private)')
    else:
        print('\n[!] DNS private IP update skipped.')
        print('    Provide --nginx-instance-id, --nginx-hosted-zone-id, and --nginx-fqdn to enable it.')
        print('    Confirm that the configured upstream hostname already resolves to NGINX\'s private IP.')

    print('\n[+] Goal B done.')
    print(f'\n    Lambda SG ID: {lambda_sg_id}')
    print('    *** SAVE THIS - cleanup can also rediscover it from the API ID ***')
    print('\n    Review NGINX allow/deny rules and confirm they permit the Lambda traffic.')
    print('\n    WARNING: an infrastructure redeployment may restore the original SG rules.')
    print('    Re-run this script with --vpc-hardening after such a redeployment.')
    print('    Run with --cleanup-vpc-hardening before Terraform destroy.')


if __name__ == '__main__':
    main()
