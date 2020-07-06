#!/usr/bin/python

# Copyright 2019 VMware Inc
# All Rights Reserved
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

import optparse
import re
import sys
import uuid

import requests
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning

EXIT_CODE_REQUIRED_ARGS_MISSING = 1
EXIT_CODE_CLEANUP_NSX_RESOURCE_FAILED = 2
EXIT_CODE_TOP_TIER_ROUTER_MISSING = 3
EXIT_CODE_MULTI_TOP_TIER_ROUTERS_FOUND = 4


class NSXClient(object):
    """Base NSX REST client"""

    def __init__(self, host, username, password, nsx_cert, key,
                 ca_cert, cluster, remove, top_tier_router_id, all_res):
        self.host = host
        self.username = username
        self.password = password
        self.nsx_cert = nsx_cert
        self.key = key
        self.use_cert = bool(self.nsx_cert and self.key)
        self.ca_cert = ca_cert
        self._cluster = cluster
        self._cluster_uuid_str = str(uuid.uuid5(uuid.NAMESPACE_X500, cluster))
        self._remove = remove
        self._top_tier_router_id = top_tier_router_id
        self._all_res = all_res
        self.resource_to_url = {
            'PolicyDomain': '/infra/domains',
            'PolicyTier-0': '/infra/tier-0s',
            'PolicyTier-1': '/infra/tier-1s',
            'PolicySecurityPolicy': (
                '/infra/domains/%(domain)s/security-policies'),
            'PolicyService': '/infra/services',
            'PolicyGroup': '/infra/domains/%(domain)s/groups',
            'PolicyLBService': '/infra/lb-services',
            'PolicyLBVirtualServer': '/infra/lb-virtual-servers',
            'PolicyIPAllocation': '/infra/ip-pools/%(ip-pool)s/ip-allocations',
            'PolicyLBPool': '/infra/lb-pools',
            'PolicyLBPersistenceProfile': '/infra/lb-persistence-profiles',
            'PolicyLBAppProfile': '/infra/lb-app-profiles',
            'PolicySegment': '/infra/segments',
            'PolicyT1Segment': '/infra/tier-1s/%(Tier-1)s/segments',
            'PolicyPort': '%(parent)s/ports',
            'PolicyNatRule': '%(parent)s/nat/%(nat)s/nat-rules',
            'PolicyStaticRoute': '%(parent)s/static-routes',
            'PolicyIPSubnet': '/infra/ip-pools/%(ip-pool)s/ip-subnets',
            'PolicyIPPool': '/infra/ip-pools',
            'PolicyCertificates': '/infra/certificates',
            'PolicySpoofguardProfile': '/infra/spoofguard-profiles',
            'PolicySegmentSecurityProfile': '/infra/segment-security-profiles',
            'PolicyIPDiscoveryProfile': '/infra/ip-discovery-profiles',
            'PolicyMACDiscoveryProfile': '/infra/mac-discovery-profiles',
            'PolicyQoSProfile': '/infra/qos-profiles',
            'PolicyPortMirroringProfile': '/infra/port-mirroring-profiles',
            'PolicyIPBlock': '/infra/ip-blocks',
            'PolicyRealizedEntity': (
                '/infra/realized-state/realized-entities?'
                'intent_path=%(intent-path)s'),
            'InventoryCluster': '/fabric/container-clusters'
        }
        self.header = {'X-Allow-Overwrite': 'true'}
        self.authenticate()
        self._top_tier_router = self._get_top_tier_router()
        self._cleanup_errors = []

    def _get_top_tier_router(self):
        if self._top_tier_router_id:
            router_response = self.get_tier_0_by_id(self._top_tier_router_id)
            if router_response.get('httpStatus') == 'NOT_FOUND':
                top_tier_routers = []
            else:
                return router_response
            router_response = self.get_tier_1_by_id(self._top_tier_router_id)
            if router_response.get('httpStatus') == 'NOT_FOUND':
                top_tier_routers = []
            else:
                return router_response
        else:
            top_tier_routers = self.get_ncp_tier_0s()
            if not top_tier_routers:
                top_tier_routers = self.get_ncp_tier_1s()
        if not top_tier_routers:
            print("Error: Missing cluster top-tier router")
            sys.exit(EXIT_CODE_TOP_TIER_ROUTER_MISSING)
        if len(top_tier_routers) > 1:
            print("Found %d top-tier routers " %
                  len(top_tier_routers))
            sys.exit(EXIT_CODE_MULTI_TOP_TIER_ROUTERS_FOUND)
        return top_tier_routers[0]

    def _resource_url(self, resource_type):
        if resource_type.startswith('Policy'):
            prefix = '/policy/api/v1'
            return self.host + prefix + self.resource_to_url[resource_type]
        else:
            return self.host + '/api/v1' + self.resource_to_url[resource_type]

    def _policy_resource_url_by_path(self, path):
        return self.host + '/policy/api/v1' + path

    def make_get_call(self, full_url, params={}):
        if self.use_cert:
            return requests.get('https://' + full_url, cert=(self.nsx_cert,
                                                             self.key),
                                headers=self.header, params=params,
                                verify=False).json()
        else:
            return requests.get('https://' + full_url, auth=(self.username,
                                                             self.password),
                                headers=self.header, params=params,
                                verify=False).json()

    def make_post_call(self, full_url, body, params={}):
        if self.use_cert:
            return requests.post('https://' + full_url, cert=(self.nsx_cert,
                                                             self.key),
                                headers=self.header, params=params,
                                verify=False, json=body)
        else:
            return requests.post('https://' + full_url, auth=(self.username,
                                                             self.password),
                                headers=self.header, params=params,
                                verify=False, json=body)

    def make_delete_call(self, full_url, params={}):
        if self.use_cert:
            return requests.delete('https://' + full_url, cert=(self.nsx_cert,
                                                                self.key),
                                   headers=self.header, params=params,
                                   verify=False)
        else:
            return requests.delete('https://' + full_url, auth=(self.username,
                                                                self.password),
                                   headers=self.header, params=params,
                                   verify=False)

    def get_resource_by_type(self, resource_type, parent=None):
        resource_url = self._resource_url(resource_type)
        if parent:
            resource_url = resource_url % parent
        print(resource_url)
        res = []
        r_json = self.make_get_call(resource_url)
        while 'cursor' in r_json:
            res += r_json['results']
            url_with_paging = resource_url + '?' + 'cursor=' + r_json['cursor']
            r_json = self.make_get_call(url_with_paging)
        res += r_json.get('results', [])
        return res

    def get_resource_by_type_and_id(self, resource_type, uuid, parent=None):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        if parent:
            resource_url = resource_url % parent
        print(resource_url)
        return self.make_get_call(resource_url)

    def delete_resource_by_type_and_id(self, resource_type, uuid):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        print(resource_url)
        res = self.make_delete_call(resource_url)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)

    def get_policy_resource_by_path(self, path, params={}):
        resource_url = self._policy_resource_url_by_path(path)
        print(resource_url)
        return self.make_get_call(resource_url, params=params)

    def delete_policy_resource_by_path(self, path, params={}, force=0):
        '''
            force: 0: Do not delete children and reference
                   1: Delete children
                   2: Delete children and reference
        '''
        resource_url = self._policy_resource_url_by_path(path)
        print(resource_url)
        res = self.make_delete_call(resource_url, params=params)
        if force and res.status_code == requests.codes.bad_request:
            r_json = res.json()
            if r_json['error_code'] == 500030:
                childs = re.findall('[\[](.*?)[\]]', r_json['error_message'])
                childs = childs[1].split(',')
            elif r_json['error_code'] in [520009, 520013]:
                childs = re.findall('[\[](.*?)[\]]', r_json['error_message'])
                childs = childs[0].split(',')
            elif r_json['error_code'] == 503093:
                return r_json['error_code']
            else:
                raise Exception(res.text)
            if force == 1:
                print('Deleting children')
            else:
                print('Deleting children and reference')
            childs.reverse()
            for child in childs:
                if force == 1 and not child.startswith(path):
                    continue
                self.delete_policy_resource_by_path(child, force=force)
            self.delete_policy_resource_by_path(path, params=params)
        elif res.status_code != requests.codes.ok:
            raise Exception(res.text)

    def get_segment_ports(self):
        """
        Retrieve all segment ports on NSX backend
        """
        segments = self.get_segments()
        segment_ports = []
        for segment in segments:
            ports = self.get_resource_by_type(
                'PolicyPort', parent={'parent': segment['path']})
            segment_ports.extend(ports)
        return segment_ports

    def get_ncp_segment_ports(self):
        """
        Retrieve all segment ports created by NCP
        """
        lports = self.get_ncp_resources(
            self.get_segment_ports())
        return lports

    def _cleanup_segment_ports(self, lports):
        # segment port vif detachment
        for lport in lports:
            if self.is_node_lsp(lport):
                continue
            try:
                result = self.delete_policy_resource_by_path(
                    lport['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete segment port %s, error %s" %
                    (lport['id'], e))
            else:
                if result:
                    print("No need to delete segment port %s" % lport['id'])
                else:
                    print("Successfully deleted segment port %s" % lport['id'])

    def cleanup_ncp_segment_ports(self):
        """
        Delete all segment ports created by NCP
        """
        ncp_lports = self.get_ncp_segment_ports()
        print("Number of NCP segment Ports to be deleted: %s" %
              len(ncp_lports))
        if not self._remove:
            return
        self._cleanup_segment_ports(ncp_lports)

    def is_node_lsp(self, lport):
        # Node Segment Port can be updated by NCP to be parent VIF type
        # For SegmentPort of node, it does not have "attachment" filed
        if not lport.get('attachment'):
            return True
        if lport['attachment'].get('type', 'PARENT') == 'PARENT':
            return True
        return False

    def _is_ncp_resource(self, tags):
        return any(tag.get('scope') == 'ncp/cluster' and
                   tag.get('tag') == self._cluster for tag in tags)

    def _is_ncp_ha_resource(self, tags):
        return any(tag.get('scope') == 'ncp/ha' and
                   tag.get('tag') == 'true' for tag in tags)

    def _is_ncp_shared_resource(self, tags):
        return any(tag.get('scope') == 'ncp/shared_resource' and
                   tag.get('tag') == 'true' for tag in tags)

    def get_ncp_resources(self, resources):
        """
        Get all logical resources created by NCP
        """
        ncp_resources = [r for r in resources if 'tags' in r
                         if self._is_ncp_resource(r['tags'])]
        return ncp_resources

    def get_ncp_shared_resources(self, resources):
        """
        Get all logical resources with ncp/cluster tag
        """
        ncp_shared_resources = [r for r in resources if 'tags' in r
                                if self._is_ncp_shared_resource(r['tags'])]
        return ncp_shared_resources

    def get_segments(self):
        """
        Retrieve all segments on NSX backend
        """
        segments = self.get_resource_by_type('PolicySegment')
        tier_1s = self.get_resource_by_type('PolicyTier-1')
        for tier_1 in tier_1s:
            tier_1_segments = self.get_resource_by_type(
                'PolicyT1Segment', parent={'Tier-1': tier_1['id']})
            segments.extend(tier_1_segments)
        return segments

    def get_ncp_segments(self):
        """
        Retrieve all segments created from NCP
        """
        segments = self.get_ncp_resources(
            self.get_segments())

        return segments

    def get_cidr_from_ip_pool(self, ip_pool):
        subnets = self.get_resource_by_type('PolicyIPSubnet',
                                           parent={'ip-pool': ip_pool['id']})
        cidr = None
        for subnet in subnets:
            entities = self.get_realized_entity(subnet['path'])
            for entity in entities:
                if (entity['entity_type'] == 'IpBlockSubnet' and
                    entity['state'] == 'REALIZED'):
                    for attr in entity.get('extended_attributes', []):
                        if attr['key'] == 'cidr':
                            cidr = attr['values'][0]
                            return cidr
        return

    def cleanup_ncp_segments(self):
        """
        Delete all segments created from NCP
        """
        segments = self.get_ncp_segments()
        print("Number of Segments to be deleted: %s" %
              len(segments))
        for ls in segments:
            # Check if there are still ports on switch and blow them away
            # An example here is a metadata proxy port (this is not stored
            # in the DB so we are unable to delete it when reading ports
            # from the DB)
            lports = self.get_resource_by_type('PolicyPort',
                                               parent={'parent': ls['path']})
            if lports:
                print("Number of orphan Segment Ports to be "
                      "deleted: %s for ls %s" % (len(lports),
                                                 ls['display_name']))
                if self._remove:
                    self._cleanup_segment_ports(lports)
            if not self._remove:
                continue
            try:
                self.delete_policy_resource_by_path(ls['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete segment %s-%s, "
                    "error %s" % (ls['display_name'], ls['id'], e))
            else:
                print("Successfully deleted segment %s-%s" %
                      (ls['display_name'], ls['id']))

            # Unconfigure nat rules in top-tier router
            if 'advanced_config' not in ls:
                continue
            if 'address_pool_paths' not in ls['advanced_config']:
                continue
            if not ls['advanced_config']['address_pool_paths']:
                continue
            address_pool_path = ls['advanced_config']['address_pool_paths'][0]
            try:
                ip_pool = self.get_policy_resource_by_path(address_pool_path)
            except Exception as e:
                # TODO: Needs to look into ncp log to see why
                # the pool is gone during k8s conformance test
                print("Failed to get ip_pool %s" % address_pool_path)
                continue
            cidr = self.get_cidr_from_ip_pool(ip_pool)

            # Remove router port to logical switch using router port client
            '''
            try:
                rep = self.get_resource_by_query_param(
                    'LogicalRouterPort', 'logical_switch_id', ls['id'])
                lp = rep['results']
                if lp:
                    self.delete_policy_resource_by_path(lp['path'])
            except Exception as e:
                print("Failed to delete logical router port by logical "
                      "switch %s : %s" % (ls['display_name'], e))
            else:
                print("Successfully deleted logical router port by logical "
                      "switch %s" % ls['display_name'])
            '''

            if not cidr:
                continue
            print("Unconfiguring nat rules for %s from top-tier router" %
                  cidr)
            try:
                ncp_snat_rules = self.get_ncp_snat_rules()
                ncp_snat_rule = None
                for snat_rule in ncp_snat_rules:
                    if snat_rule['source_network'] == cidr:
                        ncp_snat_rule = snat_rule
                        break
                if ncp_snat_rule:
                    self.release_snat_external_ip(ncp_snat_rule)
                    self.delete_policy_resource_by_path(ncp_snat_rule['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to unconfigure nat rule for %s "
                    "from top-tier router: %s" % (cidr, e))
            else:
                print("Successfully unconfigured nat rule for %s "
                      "from top-tier router" % cidr)

            # Finally delete the subnet and ip_pool
            try:
                print("Deleting ip_pool %s" % ip_pool['display_name'])
                self._cleanup_ip_pool(ip_pool)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete %s, error %s" %
                    (cidr, e))
            else:
                print("Successfully deleted subnet %s" % cidr)

    def get_sec_policies(self):
        """
        Retrieve all security policies
        """
        res = self.get_resource_by_type('PolicySecurityPolicy',
                                        parent={'domain': self._cluster})
        res += self.get_resource_by_type('PolicySecurityPolicy',
                                         parent={'domain': 'default'})
        return res

    def get_ncp_sec_policies(self):
        """
        Retrieve all security policies created from NCP
        """
        sec_policies = self.get_ncp_resources(
            self.get_sec_policies())
        return sec_policies

    def cleanup_ncp_sec_policies(self):
        """
        Cleanup all security policies created from NCP
        """
        sec_policies = self.get_ncp_sec_policies()
        print("Number of security policies to be deleted: %s" %
              len(sec_policies))
        if not self._remove:
            return
        for fw in sec_policies:
            try:
                self.delete_policy_resource_by_path(fw['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete security policy %s: %s" %
                    (fw['display_name'], e))
            else:
                print("Successfully deleted security policy %s" %
                      fw['display_name'])

    def get_services(self):
        """
        Retrieve all services
        """
        return self.get_resource_by_type('PolicyService')

    def get_ncp_services(self):
        """
        Retrieve all services created from NCP
        """
        services = self.get_ncp_resources(
            self.get_services())
        return services

    def cleanup_ncp_services(self):
        """
        Cleanup all services created from NCP
        """
        services = self.get_ncp_services()
        print("Number of services to be deleted: %s" %
              len(services))
        if not self._remove:
            return
        for service in services:
            try:
                self.delete_policy_resource_by_path(service['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete service %s: %s" %
                    (service['display_name'], e))
            else:
                print("Successfully deleted service %s" %
                      service['display_name'])

    def get_groups(self):
        res = self.get_resource_by_type('PolicyGroup',
                                        parent={'domain': self._cluster})
        res += self.get_resource_by_type('PolicyGroup',
                                         parent={'domain': 'default'})
        return res

    def get_ncp_groups(self):
        """
        Retrieve all Groups on NSX backend
        """
        ns_groups = self.get_ncp_resources(self.get_groups())
        return ns_groups

    def cleanup_ncp_groups(self):
        """
        Cleanup all Groups created by NCP
        """
        ns_groups = self.get_ncp_groups()
        print("Number of Groups to be deleted: %s" % len(ns_groups))
        if not self._remove:
            return
        for nsg in ns_groups:
            try:
                self.delete_policy_resource_by_path(nsg['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete Group: %s: %s" %
                    (nsg['display_name'], e))
            else:
                print("Successfully deleted Group: %s" %
                      nsg['display_name'])

    def get_tier_0s(self):
        """
        Retrieve all the tier-0 routers.
        """
        lrouters = self.get_resource_by_type('PolicyTier-0')
        return lrouters

    def get_tier_0_by_id(self, uuid):
        """
        Retrieve the tier-0 router with specified UUID.
        """
        return self.get_resource_by_type_and_id('PolicyTier-0', uuid)

    def get_ncp_tier_0s(self):
        """
        Retrieve all tier-0 routers created from vmware-nsxlib
        """
        lrouters = self.get_tier_0s()
        return self.get_ncp_resources(lrouters)

    def get_tier_1s(self):
        """
        Retrieve all the tier-1 routers.
        """
        lrouters = self.get_resource_by_type('PolicyTier-1')
        return lrouters

    def get_tier_1_by_id(self, uuid):
        """
        Retrieve the tier-1 router with specified UUID.
        """
        return self.get_resource_by_type_and_id('PolicyTier-1', uuid)

    def get_ncp_tier_1s(self):
        """
        Retrieve all tier-1 routers created from vmware-nsxlib
        """
        lrouters = self.get_tier_1s()
        return self.get_ncp_resources(lrouters)

    def get_realized_entity(self, intent_path):
        """
        Retrieve all tier-1 routers created from vmware-nsxlib
        """
        entities = self.get_resource_by_type(
            'PolicyRealizedEntity', parent={'intent-path': intent_path})
        return entities

    def get_ip_allocation_for_ip_from_pool(
            self, external_ip, external_pool_id):
        allocs = self.get_resource_by_type(
            'PolicyIPAllocation', parent={'ip-pool': external_pool_id})
        ip_alloc = None
        for alloc in allocs:
            entities = self.get_realized_entity(alloc['path'])
            for entity in entities:
                if (entity['entity_type'] == 'AllocationIpAddress' and
                    entity['state'] == 'REALIZED'):
                    for attr in entity.get('extended_attributes', []):
                        if attr['key'] == 'allocation_ip':
                            if attr['values'][0] == external_ip:
                                ip_alloc = alloc
                                return ip_alloc

        return

    def release_tier_1_external_ip(self, lr):
        external_ip = None
        external_pool_id = None
        if 'tags' in lr:
            for tag in lr['tags']:
                if tag.get('scope') == 'ncp/extpoolid':
                    external_pool_id = tag.get('tag')
                if tag.get('scope') == 'ncp/snat_ip':
                    external_ip = tag.get('tag')
        if not external_pool_id:
            return
        if not external_ip:
            return
        print("External ip %s to be released from pool %s" %
              (external_ip, external_pool_id))
        ip_alloc = self. get_ip_allocation_for_ip_from_pool(
            external_ip, external_pool_id)
        if not ip_alloc:
            return
        if not self._remove:
            return
        try:
            self.delete_policy_resource_by_path(ip_alloc['path'])
        except Exception as e:
            self._cleanup_errors.append(
                "ERROR: Failed to release ip %s from external_pool %s, "
                "error %s" % (external_ip, external_pool_id, e))
        else:
            print("Successfully release ip %s from external_pool %s"
                  % (external_ip, external_pool_id))

    def release_snat_external_ip(self, snat_rule):
        print("Releasing translated_network for snat %s" % snat_rule['id'])
        external_pool_id = None
        if 'tags' in snat_rule:
            for tag in snat_rule['tags']:
                if tag.get('scope') == 'ncp/extpoolid':
                    external_pool_id = tag.get('tag')
                    break
        if not external_pool_id:
            return
        external_ip = snat_rule.get('translated_network')
        if not external_ip:
            return
        print("External ip %s to be released from pool %s" %
              (external_ip, external_pool_id))
        ip_alloc = self. get_ip_allocation_for_ip_from_pool(
            external_ip, external_pool_id)
        if not ip_alloc:
            return
        if not self._remove:
            return
        try:
            self.delete_policy_resource_by_path(ip_alloc['path'])
        except Exception as e:
            self._cleanup_errors.append(
                "ERROR: Failed to release ip %s from external_pool %s, "
                "error %s" % (external_ip, external_pool_id, e))
        else:
            print("Successfully release ip %s from external_pool %s"
                  % (external_ip, external_pool_id))

    def cleanup_ncp_tier_1s(self):
        """
        Delete all Tier-1s created by NCP
        We also need to release the ip assigned from external pool
        """
        lrouters = self.get_ncp_tier_1s()
        print("Number of Tier-1s to be deleted: %s" %
              len(lrouters))
        for lr in lrouters:
            self.release_tier_1_external_ip(lr)
            if not self._remove:
                continue
            try:
                self.delete_policy_resource_by_path(lr['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete tier-1 %s-%s, "
                    "error %s" % (lr['display_name'], lr['id'], e))
            else:
                print("Successfully deleted tier-1 %s-%s" %
                      (lr['display_name'], lr['id']))

    def get_ip_pools(self):
        """
        Retrieve all ip_pools on NSX backend
        """
        return self.get_resource_by_type('PolicyIPPool')

    def get_ncp_ip_pools(self):
        """
        Retrieve all logical switches created from NCP
        """
        ip_pools = self.get_ncp_resources(
            self.get_ip_pools())

        return ip_pools

    def _cleanup_ip_pool(self, ip_pool):
        if not ip_pool:
            return
        allocs = self.get_resource_by_type('PolicyIPAllocation',
                                           parent={'ip-pool': ip_pool['id']})

        print("Number of IPs to be released %s" % len(allocs))
        for alloc in allocs:
            try:
                self.delete_policy_resource_by_path(alloc['path'], force=1)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to release ip %s from Ip pool %s "
                    "error: %s" % (alloc['path'], ip_pool['id'], e))
        self.delete_policy_resource_by_path(ip_pool['path'], force=1)

    def cleanup_ncp_ip_pools(self):
        """
        Delete all ip pools created from NCP
        """
        ip_pools = self.get_ncp_ip_pools()
        print("Number of IP Pools to be deleted: %s" %
              len(ip_pools))
        if not self._remove:
            return
        for ip_pool in ip_pools:
            if 'tags' in ip_pool:
                is_external = False
                for tag in ip_pool['tags']:
                    if (tag.get('scope') == 'ncp/external' and
                        tag.get('tag') == 'true'):
                        is_external = True
                        break
                if is_external:
                    continue
            try:
                self._cleanup_ip_pool(ip_pool)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete ip pool %s:%s, "
                    "error %s" % (ip_pool['display_name'],
                                  ip_pool['id'], e))
            else:
                print("Successfully deleted ip pool %s-%s" %
                      (ip_pool['display_name'], ip_pool['id']))

    def cleanup_ncp_lb_services(self):
        lb_services = self.get_ncp_lb_services()
        print("Number of Loadbalance services to be deleted: %s" %
              len(lb_services))
        if not self._remove:
            return
        for lb_svc in lb_services:
            try:
                self.delete_policy_resource_by_path(lb_svc['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete lb_service %s-%s, error %s" %
                    (lb_svc['display_name'], lb_svc['id'], e))
            else:
                print("Successfully deleted lb_service %s-%s" %
                      (lb_svc['display_name'], lb_svc['id']))

    def get_ncp_lb_services(self):
        lb_services = self.get_lb_services()
        return self.get_ncp_resources(lb_services)

    def get_lb_services(self):
        return self.get_resource_by_type('PolicyLBService')

    def cleanup_ncp_lb_virtual_servers(self):
        lb_virtual_servers = self.get_ncp_lb_virtual_servers()
        print("Number of loadbalancer virtual servers to be deleted: %s" %
              len(lb_virtual_servers))
        for lb_vs in lb_virtual_servers:
            self.release_lb_virtual_server_external_ip(lb_vs)
            if not self._remove:
                continue
            try:
                self.delete_policy_resource_by_path(lb_vs['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete lv_virtual_server %s-%s, "
                    "error %s" % (lb_vs['display_name'], lb_vs['id'], e))
            else:
                print("Successfully deleted lv_virtual_server %s-%s" %
                      (lb_vs['display_name'], lb_vs['id']))

    def release_lb_virtual_server_external_ip(self, lb_vs):
        if 'ip_address' not in lb_vs:
            return
        external_ip = lb_vs['ip_address']
        external_pool_id = None
        if 'tags' in lb_vs:
            for tag in lb_vs['tags']:
                if tag.get('scope') == 'ncp/ip_pool_id':
                    external_pool_id = tag.get('tag')
        if not external_pool_id:
            return

        print("Releasing external IP %s-%s "
              "of lb virtual server %s from external pool %s" %
              (lb_vs['display_name'], lb_vs['id'],
               external_ip, external_pool_id))
        ip_alloc = self. get_ip_allocation_for_ip_from_pool(
            external_ip, external_pool_id)
        if not ip_alloc:
            return
        if not self._remove:
            return
        try:
            self.delete_policy_resource_by_path(ip_alloc['path'])
        except Exception as e:
            self._cleanup_errors.append(
                "ERROR: Failed to release ip %s from external_pool %s, "
                "error %s" % (external_ip, external_pool_id, e))
        else:
            print("Successfully release ip %s from external_pool %s"
                  % (external_ip, external_pool_id))

    def get_ncp_lb_virtual_servers(self):
        lb_virtual_servers = self.get_virtual_servers()
        return self.get_ncp_resources(lb_virtual_servers)

    def get_virtual_servers(self):
        return self.get_resource_by_type('PolicyLBVirtualServer')

    def cleanup_ncp_lb_pools(self):
        lb_pools = self.get_ncp_lb_pools()
        print("Number of loadbalancer pools to be deleted: %s" %
              len(lb_pools))
        if not self._remove:
            return
        for lb_pool in lb_pools:
            try:
                self.delete_policy_resource_by_path(lb_pool['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete lb_pool %s-%s, "
                    "error %s" % (lb_pool['display_name'],
                                  lb_pool['id'], e))
            else:
                print("Successfully deleted lb_pool %s-%s" %
                      (lb_pool['display_name'], lb_pool['id']))

    def get_ncp_lb_pools(self):
        lb_pools = self.get_lb_pools()
        return self.get_ncp_resources(lb_pools)

    def get_lb_pools(self):
        return self.get_resource_by_type('PolicyLBPool')

    def cleanup_ncp_persistence_profiles(self):
        persistence_profiles = self.get_ncp_persistence_profiles()
        print("Number of persistence profiles rules to be deleted: %s" %
              len(persistence_profiles))
        if not self._remove:
            return
        for persistence_profile in persistence_profiles:
            try:
                self.delete_policy_resource_by_path(
                    persistence_profile['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete persistence profile %s-%s, "
                    "error %s" % (persistence_profile['display_name'],
                                  persistence_profile['id'], e))
            else:
                print("Successfully deleted persistence profile %s-%s" %
                      (persistence_profile['display_name'],
                       persistence_profile['id']))

    def get_ncp_persistence_profiles(self):
        return self.get_ncp_resources(
            self.get_resource_by_type('PolicyLBPersistenceProfile'))

    def get_ip_blocks(self):
        return self.get_resource_by_type('PolicyIPBlock')

    def get_ncp_ip_blocks(self):
        ip_blocks = self.get_ip_blocks()
        return self.get_ncp_resources(ip_blocks)

    def get_switching_profiles(self):
        sw_profiles = []
        s_types = ['PolicySpoofguardProfile', 'PolicySegmentSecurityProfile',
                 'PolicyIPDiscoveryProfile', 'PolicyMACDiscoveryProfile',
                 'PolicyQoSProfile', 'PolicyPortMirroringProfile']
        for s_type in s_types:
            sw_profiles.extend(self.get_resource_by_type(s_type))
        return sw_profiles

    def get_ncp_switching_profiles(self):
        sw_profiles = self.get_switching_profiles()
        return self.get_ncp_resources(sw_profiles)

    def get_application_profiles(self):
        app_profiles = self.get_resource_by_type('PolicyLBAppProfile')
        return app_profiles

    def get_ncp_application_profiles(self):
        app_profiles = self.get_application_profiles()
        return self.get_ncp_resources(app_profiles)

    def get_l7_resource_certs(self):
        return self.get_resource_by_type('PolicyCertificates')

    def get_ncp_l7_resource_certs(self):
        l7_resource_certs = self.get_l7_resource_certs()
        return self.get_ncp_resources(l7_resource_certs)

    '''
    def cleanup_cert(self):
        if self.nsx_cert and self.key:
            try:
                os.close(self.fd)
                os.remove(self.certpath)
                print("Certificate file %s for NSX client connection "
                      "has been removed" % self.certpath)
            except OSError as e:
                print("Error when during cert file cleanup %s" % e)
    '''

    def get_nat_rules(self):
        """
        Retrieve all nat rules on NSX backend
        """
        nat_rules = []
        for nat in ['INTERNAL', 'USER', 'DEFAULT']:
            rules = self.get_resource_by_type(
                'PolicyNatRule',
                parent={'parent': self._top_tier_router['path'], 'nat': nat})
            nat_rules.extend(rules)
        return nat_rules

    def get_snat_rules(self):
        """
        Retrieve all snat rules on NSX backend
        """
        rules = self.get_nat_rules()
        snat_rules = []
        for rule in rules:
            if rule['action'] == 'SNAT':
                snat_rules.append(rule)
        return snat_rules

    def get_ncp_snat_rules(self):
        """
        Retrieve all snat rules created from NCP
        """
        rules = self.get_ncp_resources(
            self.get_snat_rules())

        return rules

    def get_ncp_nat_rules(self):
        """
        Retrieve all nat rules created from NCP
        """
        rules = self.get_ncp_resources(
            self.get_nat_rules())

        return rules

    def cleanup_ncp_nat_rules(self):
        ncp_nat_rules = self.get_ncp_nat_rules()
        print("Number of nat rules to be deleted: %s" %
              len(ncp_nat_rules))
        if not self._remove:
            return
        for nat_rule in ncp_nat_rules:
            print(nat_rule)
            try:
                if nat_rule['action'] == 'SNAT':
                    self.release_snat_external_ip(nat_rule)
                self.delete_policy_resource_by_path(nat_rule['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete snat_rule for %s-%s, "
                    "error %s" % (nat_rule['translated_network'],
                                  nat_rule['id'], e))
            else:
                print("Successfully deleted nat_rule for %s-%s" %
                      (nat_rule.get('translated_network'), nat_rule['id']))

    def get_static_routes(self):
        """
        Retrieve all static routes on NSX backend
        """
        static_routes = self.get_resource_by_type(
            'PolicyStaticRoute',
            parent={'parent': self._top_tier_router['path']})
        return static_routes

    def get_ncp_static_routes(self):
        """
        Retrieve all static routes created from NCP
        """
        static_routes = self.get_ncp_resources(
            self.get_static_routes())

        return static_routes

    def cleanup_ncp_static_routes(self):
        ncp_static_routes = self.get_ncp_static_routes()
        print("Number of static routes to be deleted: %s" %
              len(ncp_static_routes))
        if not self._remove:
            return
        for static_route in ncp_static_routes:
            print(static_route)
            try:
                self.delete_policy_resource_by_path(static_route['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete static_route for %s, "
                    "error %s" % (static_route['id'], e))
            else:
                print("Successfully deleted static_route for %s" %
                      (static_route['id']))

    def cleanup_ncp_ip_blocks(self):
        ip_blocks = self.get_ncp_ip_blocks()
        print("Number of ip blocks to be deleted: %s" %
              len(ip_blocks))
        if not self._remove:
            return
        for ip_block in ip_blocks:
            try:
                self.delete_policy_resource_by_path(ip_block['path'], force=2)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete ip_block %s-%s, "
                    "error %s" % (ip_block['display_name'],
                                  ip_block['id'], e))
            else:
                print("Successfully deleted ip_block %s-%s" %
                      (ip_block['display_name'], ip_block['id']))

    def cleanup_ncp_switching_profiles(self):
        ncp_switching_profiles = self.get_ncp_switching_profiles()
        print("Number of switching profiles to be deleted: %s" %
              len(ncp_switching_profiles))
        if not self._remove:
            return
        for switching_profile in ncp_switching_profiles:
            try:
                self.delete_policy_resource_by_path(switching_profile['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete switching_profile %s-%s, "
                    "error %s" % (switching_profile['display_name'],
                                  switching_profile['id'], e))
            else:
                print("Successfully deleted switching_profile %s-%s" %
                      (switching_profile['display_name'],
                       switching_profile['id']))

    def cleanup_ncp_application_profiles(self):
        ncp_app_profiles = self.get_ncp_application_profiles()
        print("Number of application profiles to be deleted: %s" %
              len(ncp_app_profiles))
        if not self._remove:
            return
        for app_profile in ncp_app_profiles:
            try:
                self.delete_policy_resource_by_path(app_profile['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete application_profile %s-%s, "
                    "error %s" % (app_profile['display_name'],
                                  app_profile['id'], e))

            else:
                print("Successfully deleted switching_profile %s-%s" %
                      (app_profile['display_name'],
                       app_profile['id']))

    def cleanup_ncp_external_ip_pools(self):
        """
        Delete all external ip pools created from NCP
        """
        ip_pools = self.get_ncp_ip_pools()
        external_ip_pools = []
        for ip_pool in ip_pools:
            if 'tags' in ip_pool:
                for tag in ip_pool['tags']:
                    if (tag.get('scope') == 'ncp/external' and
                        tag.get('tag') == 'true'):
                        external_ip_pools.append(ip_pool)
        print("Number of external IP Pools to be deleted: %s" %
              len(external_ip_pools))
        if not self._remove:
            return

        for ext_ip_pool in external_ip_pools:
            try:
                self._cleanup_ip_pool(ext_ip_pool)
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete external ip pool %s:%s, "
                    "error %s" % (ext_ip_pool['display_name'],
                                  ext_ip_pool['id'], e))
            else:
                print("Successfully deleted external ip pool %s-%s" %
                      (ext_ip_pool['display_name'], ext_ip_pool['id']))

    def cleanup_ncp_l7_resource_certs(self):
        l7_resource_certs = self.get_ncp_l7_resource_certs()
        print("Number of l7 resource certs to be deleted: %s" %
              len(l7_resource_certs))
        if not self._remove:
            return
        for l7_resource_cert in l7_resource_certs:
            try:
                self.delete_policy_resource_by_path(l7_resource_cert['path'])
            except Exception as e:
                self._cleanup_errors.append(
                    "ERROR: Failed to delete l7_resource_cert %s-%s, "
                    "error %s" % (l7_resource_cert['display_name'],
                                  l7_resource_cert['id'], e))
            else:
                print("Successfully deleted l7_resource_cert %s-%s" %
                      (l7_resource_cert['display_name'],
                       l7_resource_cert['id']))

    def cleanup_ncp_inventory(self):
        inventory = self.get_resource_by_type_and_id(
            'InventoryCluster', self._cluster_uuid_str)
        if inventory.get('resource_type', '') != 'ContainerCluster':
            print ("Inventory resource not found: %s" % self._cluster_uuid_str)
            return
        print("Inventory resource to be deleted: %s" % self._cluster_uuid_str)
        if not self._remove:
            return
        try:
            self.delete_resource_by_type_and_id(
                'InventoryCluster', self._cluster_uuid_str)
        except Exception as e:
            self._cleanup_errors.append(
                "ERROR: Failed to delete inventory resource %s, "
                "error %s" % (self._cluster_uuid_str, e))
        else:
            print("Successfully deleted inventory resource %s" %
                  self._cluster_uuid_str)

    def authenticate(self):
        # make a get call to make sure response is not forbidden
        full_url = self._resource_url('PolicyDomain')
        if self.use_cert:
            response = requests.get('https://' + full_url, cert=(self.nsx_cert,
                                                                 self.key),
                                headers=self.header,
                                verify=False)
        else:
            response = requests.get('https://' + full_url,
                                    auth=(self.username, self.password),
                                    headers=self.header,
                                    verify=False)
        if response.status_code == requests.codes.forbidden:
            print("ERROR: Authentication failed! "
                  "Please check your credentials.")
            exit(1)

    def cleanup_all(self):
        """
        Cleanup steps:
            1. Cleanup security policies
            2. Cleanup services
            3. Cleanup Groups
            4. Cleanup loadbalancer virtual servers
            5. Cleanup loadbalancer services
            6. Cleanup loadbalancer pools
            7. Cleanup loadbalancer persistence profiles
            8. Cleanup segment ports
            9. Cleanup segments
            10.Cleanup Tier-1s
            11.Cleanup nat rules
            12.Cleanup static routes
            13.Cleanup ip pools
            14.Cleanup L7 resource certs
            15.Cleanup switching profiles
            16.Cleanup inventory resources
        """
        self.cleanup_ncp_sec_policies()
        self.cleanup_ncp_services()
        self.cleanup_ncp_groups()

        self.cleanup_ncp_lb_virtual_servers()
        self.cleanup_ncp_lb_services()
        self.cleanup_ncp_lb_pools()
        self.cleanup_ncp_persistence_profiles()

        self.cleanup_ncp_segment_ports()
        self.cleanup_ncp_segments()
        self.cleanup_ncp_tier_1s()

        self.cleanup_ncp_nat_rules()
        self.cleanup_ncp_static_routes()
        self.cleanup_ncp_ip_pools()
        self.cleanup_ncp_l7_resource_certs()
        self.cleanup_ncp_switching_profiles()
        self.cleanup_ncp_application_profiles()
        self.cleanup_ncp_inventory()
        if self._all_res:
            self.cleanup_ncp_ip_blocks()
            self.cleanup_ncp_external_ip_pools()

        if len(self._cleanup_errors) > 0:
            print("ERROR: Cleanup failed! Please try again.")
            cleanup_errors = '\n'.join(self._cleanup_errors)
            print(cleanup_errors)
            sys.exit(EXIT_CODE_CLEANUP_NSX_RESOURCE_FAILED)


def validate_options(options):
    if not options.mgr_ip or not options.cluster:
        print("Required arguments missing. Run '<script_name> -h' for usage")
        sys.exit(EXIT_CODE_REQUIRED_ARGS_MISSING)
    if (not options.password and not options.username and
        not options.nsx_cert and not options.key):
        print("Required authentication parameter missing. "
              "Run '<script_name> -h' for usage")
        sys.exit(EXIT_CODE_REQUIRED_ARGS_MISSING)


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="", dest="username",
                      help="NSX Manager username, ignored if nsx-cert is set")
    parser.add_option("-p", "--password", default="",
                      dest="password",
                      help="NSX Manager password, ignored if nsx-cert is set")
    parser.add_option("-n", "--nsx-cert", default="", dest="nsx_cert",
                      help="NSX certificate path")
    parser.add_option("-k", "--key", default="", dest="key",
                      help="NSX client private key path")
    parser.add_option("-c", "--cluster", dest="cluster",
                      help="Cluster to be removed")
    parser.add_option("-t", "--ca-cert", default="", dest="ca_cert",
                      help="NSX ca_certificate")
    parser.add_option("-r", "--remove", action='store_true',
                      dest="remove", help="CAVEAT: Removes NSX resources. "
                                          "If not set will do dry-run.")
    parser.add_option("--top-tier-router-id", dest="top_tier_router_id",
                      help="Specify the top tier router id. Must be "
                           "specified if top tier router does not have the "
                           "cluster tag")
    parser.add_option("--all-res", dest="all_res",
                      help=("Also clean up HA switching profile, ipblock, "
                            "external ippool. These resources could be "
                            "created by PAS NSX-T Tile"), action='store_true')
    parser.add_option("--no-warning", action="store_true", dest="no_warning",
                      help="Disable urllib's insecure request warning")
    (options, args) = parser.parse_args()

    if options.no_warning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

    validate_options(options)
    # Get NSX REST client
    nsx_client = NSXClient(host=options.mgr_ip,
                           username=options.username,
                           password=options.password,
                           nsx_cert=options.nsx_cert,
                           key=options.key,
                           ca_cert=options.ca_cert,
                           cluster=options.cluster,
                           remove=options.remove,
                           top_tier_router_id=options.top_tier_router_id,
                           all_res=options.all_res)
    nsx_client.cleanup_all()
