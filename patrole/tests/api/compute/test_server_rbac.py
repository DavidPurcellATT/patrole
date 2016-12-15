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

from patrole.tests.api import rbac_base

from patrole import rbac_exceptions
from patrole import rbac_rule_validation
from patrole.rbac_utils import rbac_utils
from tempest.lib.common.utils import data_utils
#TODO: Should be lib
from tempest.common import waiters
from tempest.lib.common.utils import test_utils

from tempest import config
from patrole import test

from tempest.lib import exceptions as lib_exc


CONF = config.CONF
LOG = logging.getLogger(__name__)


class RbacServerTestJSON(rbac_base.BaseV2ComputeRbacTest):

    # Testcases which do not need server already present.

    @classmethod
    def setup_credentials(cls):
        super(RbacServerTestJSON, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(RbacServerTestJSON, cls).setup_clients()
        cls.client = cls.servers_client

    def tearDown(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        self.clear_servers()
        super(RbacServerTestJSON, self).tearDown()

    def setUp(self):
        rbac_utils.switch_role(self, switchToRbacRole=False)
        super(RbacServerTestJSON, self).setUp()

    def _get_network_port(self, server_id):
        addr_list = self.client.list_addresses(server_id)
        nwk_name = CONF.compute.fixed_network_name
        ip_addr = addr_list['addresses'][nwk_name][0]['addr']
        port_list = self.os.ports_client.list_ports()
        for a in port_list['ports']:
            for i in a['fixed_ips']:
                if ip_addr == i['ip_address']:
                    self.port_id = a['id']
                    break

    @rbac_rule_validation.action(
        component="Compute", service="nova", rule="compute:create")
    @test.idempotent_id('4f34c73a-6ddc-4677-976f-71320fa855bd')
    def test_create_server(self, **kwargs):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.create_test_server(wait_until='ACTIVE')
        except lib_exc.ServerFault as e:
            # Some other policy may have blocked it.
            LOG.info("ServerFualt exception caught. Some other policy "
                     "blocked creation of server")
            raise rbac_exceptions.RbacActionFailed(e)
    
    @rbac_rule_validation.action(component="Compute", service="nova",
                                 rule="compute:update")
    @test.idempotent_id('077b17cb-5621-43b9-8adf-5725f0d7a863')
    def test_update_server(self, **kwargs):

        server = self.create_test_server(wait_until='ACTIVE')
        new_name = data_utils.rand_name('server')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.client.update_server(server['id'], name=new_name)
        except lib_exc.ServerFault as e:
            # Some other policy may have blocked it.
            LOG.info("ServerFualt exception caught. Some other policy "
                     "blocked updating of server")
            raise rbac_exceptions.RbacActionFailed(e)
    
    @rbac_rule_validation.action(component="Compute", service="nova",
                                 rule="compute:delete")
    @test.idempotent_id('062e3440-e873-4b41-9317-bf6d8be50c12')
    def test_delete_server(self, **kwargs):
        server = self.create_test_server(wait_until='ACTIVE')

        # Get the port being used. It will have to be deleted
        # for non-admin user.
        self._get_network_port(server['id'])
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.os.ports_client.delete_port, self.port_id)

    
    @rbac_rule_validation.action(
        component="Compute", service="nova", rule="compute:force_delete")
    @test.idempotent_id('864d5e4c-64f8-49a9-8573-d23d562a519d')
    def test_force_delete_server(self, **kwargs):
        server = self.create_test_server(wait_until='ACTIVE')

        # Get the port being used. It will have to be deleted
        # for non-admin user.
        self._get_network_port(server['id'])

        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.force_delete_server(server['id'])
        waiters.wait_for_server_termination(self.client, server['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.os.ports_client.delete_port, self.port_id)
 
    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:admin_actions:resetNetwork")
    @test.idempotent_id('e931f67d-247e-4fad-b306-9a37497556f3')
    def test_reset_network_server(self):
        # Reset Network of a Server
        server = self.create_test_server(wait_until='ACTIVE')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.reset_network(server['id'])
    
    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:admin_actions:injectNetworkInfo")
    @test.idempotent_id('14b9f257-f265-477e-8999-2f3196da8622')
    def test_inject_network_info_server(self):
        # Reset Network of a Server
        server = self.create_test_server(wait_until='ACTIVE')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        # Inject the Network Info into Server
        self.client.inject_network_info(server['id'])
    
    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:admin_actions:migrateLive")
    @test.idempotent_id('532ff6d0-b3f7-464b-8211-9c4b75180228')
    def test_migration_live(self):
        # Create a fake host to migrate. If a user is allowed, BadRequest
        # will be thrown else Forbidden will be thrown.
        target_host = 'SomeHost'
        server = self.create_test_server(wait_until='ACTIVE')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.client.live_migrate_server(
                server['id'], host=target_host, block_migration=False,
                disk_over_commit=False)
        except lib_exc.BadRequest:
            pass
    
    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:admin_actions:migrate")
    @test.idempotent_id('5a8c6ac1-7061-429c-8729-485c799426ac')
    def test_migration(self):
        target_host = 'SomeHost'
        server = self.create_test_server(wait_until='ACTIVE')
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.migrate_server(
            server['id'], host=target_host, block_migration=False,
            disk_over_commit=False)

    def _try_delete_aggregate(self, aggregate_id):
        # delete aggregate, if it exists
        try:
            self.os.aggregates_client.delete_aggregate(aggregate_id)
        # if aggregate not found, it depict it was deleted in the test
        except lib_exc.NotFound:
            pass

    
    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:aggregates")
    @test.idempotent_id('f4fcace1-317c-4448-b873-17a956655d85')
    def test_aggregate_list(self):
        rbac_utils.switch_role(self, switchToRbacRole=True)
        self.os.aggregates_client.list_aggregates()
    
    @rbac_rule_validation.action(
        component="Compute", service="nova",
        rule="compute_extension:agents")
    @test.idempotent_id('f8fe1447-e62e-4615-98ea-ac083e36eb09')
    def test_create_agent(self):
        # Create an agent.
        params = {'hypervisor': 'kvm', 'os': 'win', 'architecture': 'x86',
                  'version': '7.0', 'url': 'xxx://xxxx/xxx/xxx',
                  'md5hash': 'add6bb58e139be103324d04d82d8f545'}
        rbac_utils.switch_role(self, switchToRbacRole=True)
        body = self.os.agents_client.create_agent(**params)['agent']
        self.addCleanup(self.os.agents_client.delete_agent,
                        body['agent_id'])
    
#TODO:  evacuate_server not part of tempest
#    @rbac_rule_validation.action(
#        component="Compute", service="nova",
#        rule="compute_extension:evacuate")
#    @test.idempotent_id('912adf0b-7cf9-4fec-8bd8-5edc86982297')
#    def test_evacuate(self):
#        server = self.create_test_server(wait_until='ACTIVE')
#        rbac_utils.switch_role(self, switchToRbacRole=True)
#        try:
#            self.client.evacuate_server(server["id"], onSharedStorage=False)
#        except lib_exc.BadRequest:
            # Consume it. Service may still be in use. If the role was not
            # permitted, Forbidden exception should have been thrown.
#            pass
