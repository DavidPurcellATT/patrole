# Copyright 2016 AT&T Corp
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

import logging

from patrole import rbac_rule_validation
from patrole import test

from patrole.rbac_utils import rbac_utils
from patrole.tests.api import rbac_base

from tempest import config

CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacServicesTestJSON(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(RbacServicesTestJSON, cls).setup_clients()
        cls.client = cls.services_client

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(RbacServicesTestJSON, self).tearDown()

    @test.idempotent_id('ec55d455-bab2-4c36-b282-ae3af0efe287')
    @test.requires_ext(extension='os-services', service='compute')
    @rbac_rule_validation.action(
        component="Compute", service='nova',
        rule="compute_extension:services")
    def test_services_ext(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.list_services()
