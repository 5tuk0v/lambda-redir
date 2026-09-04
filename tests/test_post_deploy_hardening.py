import json
import sys
import unittest
import urllib.parse
from types import SimpleNamespace
from unittest.mock import patch

import post_deploy_hardening as hardening


def cleanup_args():
    return SimpleNamespace(
        function_name='fixture-function',
        api_id='fixtureapi',
        vpc_id='vpc-fixture',
        nginx_sg_id='sg-nginx',
        region='us-east-1',
        cleanup_timeout=60,
    )


class CleanupVpcHardeningTests(unittest.TestCase):
    @patch.object(hardening, 'aws_json')
    def test_lambda_security_group_name_does_not_use_reserved_prefix(
            self, mock_aws_json):
        mock_aws_json.return_value = {'SecurityGroups': []}

        hardening.find_lambda_security_group(cleanup_args())

        call = mock_aws_json.call_args.args
        self.assertIn('Name=group-name,Values=lambda-redir-fixtureapi', call)
        self.assertNotIn('Name=group-name,Values=sg-lambda-redir-fixtureapi', call)

    @patch.object(hardening.time, 'sleep')
    @patch.object(hardening.time, 'monotonic', side_effect=[0, 1])
    @patch.object(hardening, 'aws_run')
    @patch.object(hardening, 'aws_json')
    def test_full_cleanup_uses_safe_dependency_order(
            self, mock_aws_json, mock_aws_run, mock_monotonic, mock_sleep):
        eni_queries = 0

        def fake_aws_json(*args):
            nonlocal eni_queries
            if args[:2] == ('lambda', 'get-function-configuration'):
                return {
                    'Role': 'arn:aws:iam::111122223333:role/fixture-role',
                    'LastUpdateStatus': 'Successful',
                    'VpcConfig': {
                        'VpcId': 'vpc-fixture',
                        'SubnetIds': ['subnet-fixture'],
                        'SecurityGroupIds': ['sg-lambda'],
                    },
                }
            if args[:2] == ('ec2', 'describe-security-groups') and '--filters' in args:
                return {'SecurityGroups': [{
                    'GroupId': 'sg-lambda',
                    'GroupName': 'lambda-redir-fixtureapi',
                    'VpcId': 'vpc-fixture',
                }]}
            if args[:2] == ('ec2', 'describe-security-groups') and '--group-ids' in args:
                return {'SecurityGroups': [{
                    'GroupId': 'sg-nginx',
                    'VpcId': 'vpc-fixture',
                    'IpPermissions': [{
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'UserIdGroupPairs': [{'GroupId': 'sg-lambda'}],
                    }, {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'UserIdGroupPairs': [{'GroupId': 'sg-lambda'}],
                    }],
                }]}
            if args[:2] == ('ec2', 'describe-network-interfaces'):
                eni_queries += 1
                if eni_queries == 1:
                    return {'NetworkInterfaces': [{'NetworkInterfaceId': 'eni-fixture'}]}
                return {'NetworkInterfaces': []}
            if args[:2] == ('iam', 'list-role-policies'):
                return {'PolicyNames': ['LambdaVPCAccess']}
            if args[:2] == ('iam', 'get-role-policy'):
                return {'PolicyDocument': hardening.lambda_vpc_access_policy()}
            raise AssertionError(f'Unexpected aws_json call: {args}')

        mock_aws_json.side_effect = fake_aws_json

        hardening.cleanup_vpc_hardening(cleanup_args())

        operations = [item.args[:2] for item in mock_aws_run.call_args_list]
        self.assertEqual(operations, [
            ('ec2', 'revoke-security-group-ingress'),
            ('ec2', 'revoke-security-group-ingress'),
            ('lambda', 'update-function-configuration'),
            ('lambda', 'wait'),
            ('ec2', 'delete-security-group'),
            ('iam', 'delete-role-policy'),
        ])
        mock_sleep.assert_called_once_with(15)

    @patch.object(hardening, 'aws_run')
    @patch.object(hardening, 'aws_json')
    def test_cleanup_is_safe_to_repeat_after_resources_are_removed(
            self, mock_aws_json, mock_aws_run):
        def fake_aws_json(*args):
            if args[:2] == ('lambda', 'get-function-configuration'):
                return {
                    'Role': 'arn:aws:iam::111122223333:role/fixture-role',
                    'LastUpdateStatus': 'Successful',
                    'VpcConfig': {},
                }
            if args[:2] == ('ec2', 'describe-security-groups'):
                return {'SecurityGroups': []}
            if args[:2] == ('iam', 'list-role-policies'):
                return {'PolicyNames': []}
            raise AssertionError(f'Unexpected aws_json call: {args}')

        mock_aws_json.side_effect = fake_aws_json

        hardening.cleanup_vpc_hardening(cleanup_args())

        mock_aws_run.assert_not_called()

    @patch.object(hardening, 'aws_run')
    @patch.object(hardening, 'aws_json')
    def test_cleanup_refuses_unrecognized_lambda_vpc_configuration(
            self, mock_aws_json, mock_aws_run):
        def fake_aws_json(*args):
            if args[:2] == ('lambda', 'get-function-configuration'):
                return {
                    'Role': 'arn:aws:iam::111122223333:role/fixture-role',
                    'LastUpdateStatus': 'Successful',
                    'VpcConfig': {
                        'VpcId': 'vpc-fixture',
                        'SecurityGroupIds': ['sg-unrelated'],
                    },
                }
            if args[:2] == ('ec2', 'describe-security-groups'):
                return {'SecurityGroups': []}
            raise AssertionError(f'Unexpected aws_json call: {args}')

        mock_aws_json.side_effect = fake_aws_json

        with self.assertRaises(SystemExit):
            hardening.cleanup_vpc_hardening(cleanup_args())

        mock_aws_run.assert_not_called()

    def test_nginx_reference_requires_exact_goal_b_rule(self):
        nginx_sg = {
            'IpPermissions': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'UserIdGroupPairs': [{'GroupId': 'sg-lambda'}],
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'UserIdGroupPairs': [{'GroupId': 'sg-other'}],
                },
            ],
        }

        self.assertTrue(hardening.nginx_references_lambda_sg(nginx_sg, 'sg-lambda', 443))
        self.assertFalse(hardening.nginx_references_lambda_sg(nginx_sg, 'sg-lambda', 80))
        self.assertTrue(hardening.nginx_references_lambda_sg(nginx_sg, 'sg-other', 80))

    def test_policy_document_normalization_accepts_aws_url_encoding(self):
        expected = hardening.lambda_vpc_access_policy()
        encoded = urllib.parse.quote(json.dumps(expected), safe='')

        self.assertEqual(hardening.normalize_policy_document(encoded), expected)
        self.assertEqual(hardening.normalize_policy_document(expected), expected)
        self.assertIsNone(hardening.normalize_policy_document('%not-json'))

    @patch.object(hardening, 'aws_run')
    @patch.object(hardening, 'aws_json')
    def test_cleanup_refuses_to_delete_unrecognized_inline_policy(
            self, mock_aws_json, mock_aws_run):
        def fake_aws_json(*args):
            if args[:2] == ('lambda', 'get-function-configuration'):
                return {
                    'Role': 'arn:aws:iam::111122223333:role/fixture-role',
                    'LastUpdateStatus': 'Successful',
                    'VpcConfig': {},
                }
            if args[:2] == ('ec2', 'describe-security-groups'):
                return {'SecurityGroups': []}
            if args[:2] == ('iam', 'list-role-policies'):
                return {'PolicyNames': ['LambdaVPCAccess']}
            if args[:2] == ('iam', 'get-role-policy'):
                return {'PolicyDocument': {'Version': 'unrelated'}}
            raise AssertionError(f'Unexpected aws_json call: {args}')

        mock_aws_json.side_effect = fake_aws_json

        with self.assertRaises(SystemExit):
            hardening.cleanup_vpc_hardening(cleanup_args())

        mock_aws_run.assert_not_called()


class CommandLineCompatibilityTests(unittest.TestCase):
    @patch.object(hardening.time, 'sleep')
    @patch.object(hardening.time, 'monotonic', side_effect=[0, 1])
    @patch.object(hardening.subprocess, 'run')
    def test_lambda_vpc_attach_retries_iam_propagation(
            self, mock_subprocess_run, mock_monotonic, mock_sleep):
        mock_subprocess_run.side_effect = [
            SimpleNamespace(
                returncode=255,
                stdout='',
                stderr='The provided execution role does not have permissions '
                       'to call CreateNetworkInterface on EC2',
            ),
            SimpleNamespace(returncode=0, stdout='{}', stderr=''),
        ]

        hardening.aws_run_with_retry(
            'lambda', 'update-function-configuration',
            '--function-name', 'fixture-function',
        )

        self.assertEqual(mock_subprocess_run.call_count, 2)
        mock_sleep.assert_called_once_with(5)

    @patch.object(hardening, 'aws_run_with_retry')
    @patch.object(hardening, 'aws_run')
    @patch.object(hardening, 'aws_json')
    def test_goal_b_uses_described_http_https_rules_only(
            self, mock_aws_json, mock_aws_run, mock_aws_run_with_retry):
        mock_aws_json.side_effect = [
            {'Account': '111122223333'},
            {
                'Role': 'arn:aws:iam::111122223333:role/fixture-role',
                'Environment': {'Variables': {}},
            },
            {'GroupId': 'sg-lambda'},
            {
                'LastUpdateStatus': 'Successful',
                'VpcConfig': {
                    'VpcId': 'vpc-fixture',
                    'SubnetIds': ['subnet-fixture'],
                    'SecurityGroupIds': ['sg-lambda'],
                },
            },
            {'Reservations': [{'Instances': [{'PrivateIpAddress': '10.0.2.37'}]}]},
        ]
        argv = [
            'post_deploy_hardening.py',
            '--function-name', 'fixture-function',
            '--api-id', 'fixtureapi',
            '--guardrail-secret', 'fixture-secret',
            '--allowed-ip', '192.0.2.10/32',
            '--region', 'us-east-1',
            '--vpc-hardening',
            '--vpc-id', 'vpc-fixture',
            '--subnet-id', 'subnet-fixture',
            '--nginx-sg-id', 'sg-nginx',
            '--nginx-instance-id', 'i-nginx',
            '--nginx-hosted-zone-id', 'ZFIXTURE',
            '--nginx-fqdn', 'nginx.example.test',
        ]

        with patch.object(sys, 'argv', argv):
            hardening.main()

        mock_aws_run_with_retry.assert_called_once()
        self.assertTrue(any(call.args[:3] == ('lambda', 'wait', 'function-updated-v2')
                            for call in mock_aws_run.call_args_list))

        calls = [item.args for item in mock_aws_run.call_args_list]
        egress_call = next(call for call in calls
                           if call[:2] == ('ec2', 'authorize-security-group-egress'))
        ingress_call = next(call for call in calls
                            if call[:2] == ('ec2', 'authorize-security-group-ingress'))
        egress = json.loads(egress_call[egress_call.index('--ip-permissions') + 1])
        ingress = json.loads(ingress_call[ingress_call.index('--ip-permissions') + 1])

        self.assertEqual([rule['FromPort'] for rule in egress], [80, 443])
        self.assertEqual([rule['FromPort'] for rule in ingress], [80, 443])
        self.assertEqual(
            [rule['UserIdGroupPairs'][0]['GroupId'] for rule in egress],
            ['sg-nginx', 'sg-nginx'],
        )
        self.assertEqual(
            [rule['UserIdGroupPairs'][0]['Description'] for rule in egress],
            ['HTTP to NGINX', 'HTTPS to NGINX'],
        )
        self.assertEqual(
            [rule['UserIdGroupPairs'][0]['Description'] for rule in ingress],
            ['HTTP from Lambda', 'HTTPS from Lambda'],
        )

    @patch.object(hardening, 'cleanup_vpc_hardening')
    @patch.object(hardening, 'aws_run')
    @patch.object(hardening, 'aws_json')
    def test_goal_a_command_path_is_preserved(
            self, mock_aws_json, mock_aws_run, mock_cleanup):
        mock_aws_json.side_effect = [
            {'Account': '111122223333'},
            {
                'Role': 'arn:aws:iam::111122223333:role/fixture-role',
                'Environment': {'Variables': {'PRESERVED': 'yes'}},
            },
        ]
        argv = [
            'post_deploy_hardening.py',
            '--function-name', 'fixture-function',
            '--api-id', 'fixtureapi',
            '--stage', 'v2',
            '--guardrail-secret', 'fixture-secret',
            '--allowed-ip', '192.0.2.10/32',
            '--region', 'us-east-1',
            '--debug-lambda',
        ]

        with patch.object(sys, 'argv', argv):
            hardening.main()

        mock_cleanup.assert_not_called()
        self.assertEqual(len(mock_aws_run.call_args_list), 3)

        environment_call = mock_aws_run.call_args_list[0].args
        environment = json.loads(environment_call[environment_call.index('--environment') + 1])
        self.assertEqual(environment['Variables']['PRESERVED'], 'yes')
        self.assertEqual(environment['Variables']['GUARDRAIL_VALUE'], 'fixture-secret')
        self.assertEqual(environment['Variables']['DEBUG'], '1')

        policy_call = mock_aws_run.call_args_list[1].args
        patch_document = json.loads(policy_call[policy_call.index('--patch-operations') + 1])
        policy = json.loads(patch_document[0]['value'])
        self.assertEqual(
            policy['Statement'][1]['Condition']['NotIpAddress']['aws:SourceIp'],
            '192.0.2.10/32',
        )

        self.assertEqual(
            mock_aws_run.call_args_list[2].args[:2],
            ('apigateway', 'create-deployment'),
        )

    @patch.object(hardening, 'cleanup_vpc_hardening')
    @patch.object(hardening, 'aws_json')
    def test_cleanup_command_does_not_require_goal_a_arguments(
            self, mock_aws_json, mock_cleanup):
        mock_aws_json.return_value = {'Account': '111122223333'}
        argv = [
            'post_deploy_hardening.py',
            '--function-name', 'fixture-function',
            '--api-id', 'fixtureapi',
            '--cleanup-vpc-hardening',
            '--vpc-id', 'vpc-fixture',
            '--nginx-sg-id', 'sg-nginx',
            '--region', 'us-east-1',
        ]

        with patch.object(sys, 'argv', argv):
            hardening.main()

        mock_cleanup.assert_called_once()


if __name__ == '__main__':
    unittest.main()
