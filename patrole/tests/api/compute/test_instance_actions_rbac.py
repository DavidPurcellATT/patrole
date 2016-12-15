# Copyright 2016 AT&T Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_log import log as logging

from patrole.tests.api import rbac_base

from patrole import rbac_rule_validation
from patrole.rbac_utils import rbac_utils

from tempest import config
from patrole import test

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacInstanceActionsTestJSON(rbac_base.BaseV2ComputeRbacTest):
    @classmethod
    def setup_clients(cls):
        super(RbacInstanceActionsTestJSON, cls).setup_clients()
        cls.client = cls.os.servers_client
        cls.instance_client = cls.os.instance_usages_audit_log_client

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(RbacInstanceActionsTestJSON, self).tearDown()

    def setUp(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(RbacInstanceActionsTestJSON, self).setUp()

    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:instance_actions")
    @test.idempotent_id('1e5a71f0-fe55-417f-b93a-ec29a3c29f10')
    def test_list_instance_actions(self):
        server = self.create_test_server(
            validatable=False,
            volume_backed=False)
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_instance_actions(server['id'])

    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:instance_usage_audit_log")
    @test.idempotent_id('53ec8eef-9d04-4637-ab2d-d14c6d320bbe')
    def test_list_instance_usage_audit_logs(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.instance_client.list_instance_usage_audit_logs()
