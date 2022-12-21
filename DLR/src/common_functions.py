from functools import wraps
from pprint import pprint
import time
import requests
import json
import inspect
import sys
import os
from datetime import datetime
import logging
import re
import random
import math
from math import ceil as cl
from random import shuffle
import csv
import getopt
from pprint import pformat
from functools import wraps
from pprint import pformat
from ats.topology import loader
from rest_functions import request_get, request_delete, request_post, request_put

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)

log = logging.getLogger(__name__)

ind_info_keys_list = [
    'ip',
    'username',
    'password'
]

devices_states_list = [
    'Unlicensed',
    'Licensed',
]
status_codes_list = [
    '200',
    '400',
    '404',
    '409'
]

request_headers = {'Content-Type': 'application/json'}

dlr_main_details_fields = [
    'instanceId',
    'slot',
    'ipAddress',
    'role',
    'status',
    'gatewayStatus',
    'port1',
    'port2',
    'activeSupPrecedence'
]

dlr_node_summary_fields_list = [
    'gatewayStatus',
    'instanceId',
    'port1',
    'port2',
    'slot',
]

dlr_node_summary_members_fields_dict = {
    'deviceLink': [
        'cipSlot',
        'deviceId',
        'name',
        'portName',
        'protocol',
        'slotIp',
    ],
    'index': [],
    'ipAddress': [],
    'macAddress': [],
    'role': [],
    'status': []
}


###########################################################################################################################################
###########################################################################################################################################
def handle_exception_wrapper(original_function):
    @wraps(original_function)
    def handle_exception_function(*args, **kwargs):
        try:
            return original_function(*args, **kwargs)
        except Exception as msg:
            raise Exception(str(original_function.__name__) + ':  ' + str(msg))

    return handle_exception_function


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def read_json_data(filename):
    assert type(filename) == str, 'Filename not a string'
    with open(filename, 'r') as json_file:
        json_data = json_file.read()
    return json.loads(json_data)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def read_dict_data():
    data_result = {}
    test_path = (os.path.dirname(os.path.abspath(__file__)))
    with open(test_path + '/INDStatusCodeMessage.txt', 'r') as data_file:
        for line in data_file:
            line = line.replace('\n', '')
            split_line = re.split(':', line)
            data_result[split_line[0]] = split_line[1]
    return data_result


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_delete_access_profile(self, access_profile_delete_response, access_profile_id_dict):
    assert type(access_profile_delete_response) == dict, 'Access Profile Delete Response not a dict'
    assert type(access_profile_id_dict) == dict, 'Access Profile ID Dict not a dict'
    access_profile_delete_response_count = access_profile_delete_response['recordCount']

    log.info('\tCalling Verify Pass Or Fail for DELETE Access Profiles')

    for key in access_profile_id_dict:
        for i in range(0, access_profile_delete_response_count):
            if str(access_profile_id_dict[key][0]) == str(access_profile_delete_response['records'][i]['id']):
                if str(access_profile_id_dict[key][1]) != str(access_profile_delete_response['records'][i]['success']):
                    self.failed('Failed to Delete Access Profile. Name:' + str(key) + ' ID:' + str(access_profile_id_dict[key][0]))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_get_all(self, title, status_code, expected, request_json):
    assert (type(title) == str), 'Title is not a string'
    assert str(status_code) in status_codes_list, 'Invalid status code'
    assert type(request_json) == dict, 'Request JSON not a dict'
    # verify_pass_or_fail_status_code(self, title, status_code, expected)

    log.info('\tCalling Verify Pass Or Fail for GET All by Parameter')

    param_in_dict = self.param_in
    limit_val = 2147483640
    offset_val = 0

    if param_in_dict['limit'] != 'null':
        limit_val = param_in_dict['limit']

    if param_in_dict['offset'] != 'null':
        offset_val = param_in_dict['offset']

    [get_response, get_json] = request_get(self.url_path, (self.username_in, self.password_in))
    assert (get_response.status_code == 200 and get_json['status'] == 200), 'GET response incorrect'
    total_number_of_records = get_json['recordCount']

    record_count_of_request = request_json['recordCount']
    expected_count = None

    if total_number_of_records > 0:
        total_pages = math.ceil(float(total_number_of_records) / limit_val) - 1

        if offset_val > total_pages:
            expected_count = 0
        elif offset_val == total_pages:
            if (total_number_of_records % limit_val) == 0:
                expected_count = limit_val
            else:
                expected_count = total_number_of_records % limit_val
        else:
            expected_count = limit_val

        if expected_count != record_count_of_request:
            self.failed('\tRecord Count Not As Expected')

        if record_count_of_request >= 2:
            if str(param_in_dict['direction']) == 'ASC':
                sort_param = param_in_dict['field'].split('.')[1]
                if sort_param == 'deviceAdminState':
                    sort_param = 'deviceAdminStateStr'
                for i in range(0, record_count_of_request - 1):
                    first = str(request_json['records'][i][sort_param]).lower()
                    second = str(request_json['records'][i + 1][sort_param]).lower()

                    try:
                        first = int(first)
                        second = int(second)
                    except Exception as msg:
                        pass

                    if type(first) == int and type(second) == int:
                        pass
                    else:
                        first = str(first)
                        second = str(second)

                    if first == 'none' or second == 'none':
                        continue

                    if first > second:
                        log.info(str(first) + ': ' + str(second))
                        self.failed('\tASC Not Right')

            if str(param_in_dict['direction']) == 'DESC':
                sort_param = param_in_dict['field'].split('.')[1]
                if sort_param == 'deviceAdminState':
                    sort_param = 'deviceAdminStateStr'
                for i in range(0, record_count_of_request - 1):
                    first = str(request_json['records'][i][sort_param]).lower()
                    second = str(request_json['records'][i + 1][sort_param]).lower()

                    try:
                        first = int(first)
                        second = int(second)
                    except Exception as msg:
                        pass

                    if type(first) == int and type(second) == int:
                        pass
                    else:
                        first = str(first)
                        second = str(second)

                    if first == 'none' or second == 'none':
                        continue

                    if first < second:
                        log.info(str(first) + ': ' + str(second))
                        self.failed('\tDESC Not Right')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_status_code(self, title, status_code, expected):
    assert (type(title) == str), 'Title is not a string'
    assert str(status_code) in status_codes_list, 'Invalid status code'
    ind_status_messages = read_dict_data()
    log.info('\tCalling Verify Pass Or Fail for Status Code')
    if str(expected) == str(000):
        pass
    else:
        str_in = str(status_code)
        if str(str_in) == str(expected):
            log.info('\t' + title + ' SUCCESS on status code: ' + str(' - '.join([ind_status_messages[title + str_in].split('  ')[0],
                                                                                  ind_status_messages[title + str_in].split('  ')[-1]])))
        else:
            self.failed('\t' + title + ' FAILED on Status code. Expected: ' + str(expected) + '. Got status code: ' + str_in)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_instances(self, param_in_dict, dlr_instances_list, ip_address, device_id):
    log.info('\tCalling Verify Pass Or Fail for GET DLR Instances by Group')

    if param_in_dict['empty'] == 'True' and len(dlr_instances_list) != 0:
        log.info(pformat(dlr_instances_list))
        self.failed('\tExpected empty DLR Instances by Group record')

    if param_in_dict['empty'] == 'False' and len(dlr_instances_list) == 0:
        log.info(pformat(dlr_instances_list))
        self.failed('\tExpected non-zero DLR Instances by Group record')

    if param_in_dict['empty'] == 'False':

        if 'instance_id' not in param_in_dict:
            self.failed('\tInstance ID value missing')
        if 'slot' not in param_in_dict:
            self.failed('\tSlot value missing')
        if 'status' not in param_in_dict:
            self.failed('\tstatus value missing')

        if param_in_dict['instance_id'] == 'null' or param_in_dict['slot'] == 'null':
            return

        if param_in_dict['instance_id'] != 'null':
            instance_id = param_in_dict['instance_id']
        if param_in_dict['slot'] != 'null':
            slot = param_in_dict['slot']
        if param_in_dict['status'] != 'null':
            status = param_in_dict['status']

        log.info('\tDLR Instances record for Supervisor Device: ' + str(param_in_dict['ip_address']))
        sup_inst_list = [dlr_instances_list[i]['instances'] for i in range(0, len(dlr_instances_list))
                         if str(dlr_instances_list[i]['id']) == str(device_id)][0]
        log.info(pformat(sup_inst_list))

        if slot == 'None':
            sup_instance = str(instance_id)
            sup_slot = [sup_inst_list[i]['slot'] for i in range(0, len(sup_inst_list))
                        if str(sup_inst_list[i]['instanceId']) == sup_instance][0]
            sup_status = [sup_inst_list[i]['status'] for i in range(0, len(sup_inst_list))
                          if str(sup_inst_list[i]['instanceId']) == sup_instance][0]

        elif slot != 'None':
            sup_slot = str(slot)
            sup_instance = [sup_inst_list[i]['instanceId'] for i in range(0, len(sup_inst_list))
                            if str(sup_inst_list[i]['slot']) == sup_slot][0]
            sup_status = [sup_inst_list[i]['status'] for i in range(0, len(sup_inst_list))
                          if str(sup_inst_list[i]['slot']) == sup_slot][0]

        if str(sup_instance) != str(instance_id):
            log.info('\tActual Supervisor Instance ID value: ' + str(sup_instance))
            self.failed('\tSupervisor Instance ID value incorrect')

        if str(sup_slot) != str(slot):
            log.info('\tActual Supervisor Instance Slot value: ' + str(sup_slot))
            self.failed('\tSupervisor Instance Slot value incorrect')

        if str(sup_status) != str(status):
            log.info('\tActual Supervisor Instance Status value: ' + str(sup_status))
            self.failed('\tSupervisor Instance Status value incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_topology(self, param_in_dict, dlr_topology_json, ip_address, device_id):
    log.info('\tCalling Verify Pass Or Fail for GET DLR Topology by Group')

    if 'topology_template' not in param_in_dict:
        self.failed('\tDLR Topology template missing')

    test_path = str((os.path.dirname(os.path.abspath(__file__))))
    topology_template = read_json_data(test_path + '/' + str(param_in_dict['topology_template']))

    if int(dlr_topology_json['id']) != int(device_id):
        self.failed('\tSupervisor ID incorrect')

    if str(topology_template['instanceId']) != str(dlr_topology_json['instanceId']):
        self.failed('\tSupervisor Instance ID incorrect')

    if str(topology_template['status']) != str(dlr_topology_json['status']):
        self.failed('\tSupervisor Status incorrect')

    for item in topology_template['nodes']:
        node_ip = item['ipAddress']
        node_id = str(commons_retrieve_device_info_by_ip(self.ind_info, node_ip, 'id', False))
        if node_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(node_ip) + ' not in Inventory')

        node_ip_entry = [dlr_topology_json['nodes'][i] for i in range(0, len(dlr_topology_json['nodes']))
                         if int(dlr_topology_json['nodes'][i]['id']) == int(node_id)][0]

        log.info('\tDLR Node entry in GET DLR Topology by Group Result:')
        log.info(pformat(node_ip_entry))

        if str(item['slot']) != str(node_ip_entry['slot']):
            self.failed('\tDLR Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' slot incorrect')

        if str(item['role']) != str(node_ip_entry['role']):
            self.failed('\tDLR Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' role incorrect')

        if str(item['status']) != str(node_ip_entry['status']):
            self.failed('\tDLR Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' status incorrect')

        if str(item['gatewayStatus']) != str(node_ip_entry['gatewayStatus']):
            self.failed('\tDLR Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' gateway status incorrect')

    nodes_link_entry_list = []
    for item in topology_template['links']:
        source_ip = item['source']
        target_ip = item['target']
        link_status = item['status']

        source_id = str(commons_retrieve_device_info_by_ip(self.ind_info, source_ip, 'id', False))
        if source_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(source_ip) + ' not in Inventory')

        target_id = str(commons_retrieve_device_info_by_ip(self.ind_info, target_ip, 'id', False))
        if target_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(target_ip) + ' not in Inventory')

        nodes_link_entry = [dlr_topology_json['links'][i] for i in range(0, len(dlr_topology_json['links']))
                            if ((str(dlr_topology_json['links'][i]['source']) == 'D' + str(source_id)
                                 and str(dlr_topology_json['links'][i]['target']) == 'D' + str(target_id))
                                or (str(dlr_topology_json['links'][i]['source']) == 'D' + str(target_id)
                                    and str(dlr_topology_json['links'][i]['target']) == 'D' + str(source_id)))
                            and (dlr_topology_json['links'][i] not in nodes_link_entry_list)]

        if nodes_link_entry:
            nodes_link_entry_list.append(nodes_link_entry[0])
        else:
            continue

        log.info('\tDLR Link entry in GET DLR Topology by Group Result:')
        log.info(pformat(nodes_link_entry[0]))

        if str(nodes_link_entry[0]['status']) != str(link_status):
            self.failed('\tDLR Links with Source ID: D' + str(source_id) + ' and Target ID: D' + str(target_id) + ' incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_device_details(self, param_in_dict, dlr_details_json, ip_address, device_id):
    log.info('\tCalling Verify Pass Or Fail for GET DLR Device Details by ID')

    if str(param_in_dict['empty']) == 'True' and len(dlr_details_json) != 0:
        log.info(pformat(dlr_details_json))
        self.failed('\tExpected empty DLR Device Details record')

    if str(param_in_dict['empty']) == 'False' and len(dlr_details_json) == 0:
        log.info(pformat(dlr_details_json))
        self.failed('\tExpected non-zero DLR Device Details record')

    if str(param_in_dict['empty']) == 'False':
        if 'dlr_details_template' not in param_in_dict:
            self.failed('\tDLR Device Details template missing')

        if 'instance_id' not in param_in_dict:
            self.failed('\tInstance ID missing')

        test_path = str((os.path.dirname(os.path.abspath(__file__))))
        if str(param_in_dict['dlr_details_template']) != 'null':
            details_template = read_json_data(test_path + '/' + str(param_in_dict['dlr_details_template']))
        else:
            return
        if 'slot' in param_in_dict:
            details_inst_entry = [dlr_details_json[i] for i in range(0, len(dlr_details_json))
                                  if (int(dlr_details_json[i]['instanceId']) == int(param_in_dict['instance_id']))
                                  and (int(dlr_details_json[i]['slot']) == int(param_in_dict['slot']))][0]
        else:
            details_inst_entry = [dlr_details_json[i] for i in range(0, len(dlr_details_json))
                                  if int(dlr_details_json[i]['instanceId']) == int(param_in_dict['instance_id'])][0]

        log.info('\tDLR Details Instance entry in GET DLR Device Details by ID Result:')
        log.info(pformat(details_inst_entry))

        verify_pass_or_fail_dlr_main_details(self, details_template, details_inst_entry, param_in_dict)

        verify_pass_or_fail_dlr_role_details(self, details_template, details_inst_entry)

        verify_pass_or_fail_dlr_gateway_details(self, details_template, details_inst_entry)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_main_details(self, details_template, details_inst_entry, param_in_dict):
    for field in dlr_main_details_fields:
        if str(details_template[field]) != str(details_inst_entry[field]):
            log.info('\tValue for attribute: ' + str(field) + ' is: ' + str(details_inst_entry[field]))
            self.failed('\tDLR Device Details entry for Instance: ' + str(param_in_dict['instance_id']) + ' and attribute: ' +
                        str(field) + ' incorrect')

    dlr_members_ip_list = [details_inst_entry['dlrMembers'][i]['ipAddress'] for i in range(0, len(details_inst_entry['dlrMembers']))]
    dlr_members_mac_list = [details_inst_entry['dlrMembers'][i]['macAddress'] for i in range(0, len(details_inst_entry['dlrMembers']))]

    if dlr_members_ip_list != details_template['dlrMembersIP']:
        log.info('\tList of DLR members IP: ' + str(dlr_members_ip_list))
        self.failed('\tDLR members IP list incorrect')

    if dlr_members_mac_list != details_template['dlrMembersMAC']:
        log.info('\tList of DLR members MAC: ' + str(dlr_members_ip_list))
        self.failed('\tDLR members MAC list incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_role_details(self, details_template, details_inst_entry):
    if str(details_template['role']) == 'ACTIVE_SUPERVISOR':
        if str(details_inst_entry['dlrSupConfigParams'][0]['supEnabled']) != \
                str(details_template['dlrSupConfigParams'][0]['supEnabled']):
            self.failed('\tActive Supervisor enabled incorrect')

        if int(details_inst_entry['dlrSupConfigParams'][0]['precedence']) != \
                int(details_template['dlrSupConfigParams'][0]['precedence']):
            self.failed('\tActive Supervisor precedence incorrect')

    ###################################################################################################################################
    elif str(details_template['role']) == 'BACKUP_SUPERVISOR':
        if str(details_inst_entry['dlrSupConfigParams'][0]['supEnabled']) != \
                str(details_template['dlrSupConfigParams'][0]['supEnabled']):
            self.failed('\tBackup Supervisor enabled incorrect')

        if str(details_inst_entry['activeSupIpAddress']) != str(details_template['activeSupIpAddress']):
            self.failed('\tBackup Supervisor Active Supervior IP address incorrect')

        if str(details_inst_entry['activeSupMacAddress']) != str(details_template['activeSupMacAddress']):
            self.failed('\tBackup Supervisor Active Supervisor MAC address incorrect')

        assert int(details_inst_entry['activeSupPrecedence']) >= \
               int(details_inst_entry['dlrSupConfigParams'][0]['precedence']), \
            '\tBackup Supervisor precedence greater than Active Supervisor precedence'

    ###################################################################################################################################
    elif str(details_template['role']) == 'RING_NODE':
        if str(details_inst_entry['activeSupIpAddress']) != str(details_template['activeSupIpAddress']):
            self.failed('\tRing Node Active Supervior IP address incorrect')

        if str(details_inst_entry['activeSupMacAddress']) != str(details_template['activeSupMacAddress']):
            self.failed('\tRing Node Active Supervisor MAC address incorrect')

        assert len(details_inst_entry['dlrSupConfigParams']) == 0, \
            '\tRing Node Supervisor parameters list not empty'


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_gateway_details(self, details_template, details_inst_entry):
    if str(details_template['gatewayStatus']) == 'GATEWAY_NOT_ENABLED':
        assert str(details_inst_entry['activeGatewayIpAddress']) == '0.0.0.0' or \
               str(details_inst_entry['activeGatewayIpAddress']) == 'None', \
            '\tDevice with Gateway not enabled Active Gateway IP address incorrect'

        assert str(details_inst_entry['activeGatewayMacAddress']) == '00:00:00:00:00:00' or \
               str(details_inst_entry['activeGatewayMacAddress']) == 'None', \
            '\tDevice with Gateway not enabled Active Gateway MAC address incorrect'

        assert str(details_inst_entry['activeGatewayPrecedence']) == '0' or \
               str(details_inst_entry['activeGatewayPrecedence']) == 'None', \
            '\tDevice with Gateway not enabled Active Gateway Precedence incorrect'

        assert len(details_inst_entry['dlrGatewayParams']) == 0, \
            '\tDevice with Gateway not enabled Gateway parameters list not empty'

    ###################################################################################################################################
    elif str(details_template['gatewayStatus']) == 'GW_FAULT_DUE_TO_UPLINK_PORT_DOWN':
        assert str(details_inst_entry['activeGatewayIpAddress']) == '0.0.0.0' or \
               str(details_inst_entry['activeGatewayIpAddress']) == 'None', \
            '\tDevice with Gateway not enabled Active Gateway IP address incorrect'

        assert str(details_inst_entry['activeGatewayMacAddress']) == '00:00:00:00:00:00' or \
               str(details_inst_entry['activeGatewayMacAddress']) == 'None', \
            '\tDevice with Gateway not enabled Active Gateway MAC address incorrect'

        assert str(details_inst_entry['activeGatewayPrecedence']) == '0' or \
               str(details_inst_entry['activeGatewayPrecedence']) == 'None', \
            '\tDevice with Gateway not enabled Active Gateway Precedence incorrect'

        if str(details_inst_entry['dlrGatewayParams'][0]['gatewayEnabled']) != \
                str(details_template['dlrGatewayParams'][0]['gatewayEnabled']):
            self.failed('\tFault Gateway enabled incorrect')

        if int(details_inst_entry['dlrGatewayParams'][0]['precedence']) != \
                int(details_template['dlrGatewayParams'][0]['precedence']):
            self.failed('\tFault Gateway precedence incorrect')

    ###################################################################################################################################
    elif str(details_template['gatewayStatus']) == 'BACKUP_GATEWAY':
        if str(details_inst_entry['dlrGatewayParams'][0]['gatewayEnabled']) != \
                str(details_template['dlrGatewayParams'][0]['gatewayEnabled']):
            self.failed('\tBackup Gateway enabled incorrect')

        if str(details_inst_entry['activeGatewayIpAddress']) != str(details_template['activeGatewayIpAddress']):
            self.failed('\tBackup Gateway Active Gateway IP address incorrect')

        if str(details_inst_entry['activeGatewayMacAddress']) != str(details_template['activeGatewayMacAddress']):
            self.failed('\tBackup Gateway Active Gateway MAC address incorrect')

        if str(details_inst_entry['activeGatewayPrecedence']) != str(details_template['activeGatewayPrecedence']):
            self.failed('\tBackup Gateway Active Gateway Precedence incorrect')

        assert int(details_inst_entry['activeGatewayPrecedence']) >= \
               int(details_inst_entry['dlrGatewayParams'][0]['precedence']), \
            '\tBackup Gateway precedence greater than Active Gateway precedence'

    ###################################################################################################################################
    elif str(details_template['gatewayStatus']) == 'ACTIVE_GATEWAY':
        if str(details_inst_entry['dlrGatewayParams'][0]['gatewayEnabled']) != \
                str(details_template['dlrGatewayParams'][0]['gatewayEnabled']):
            self.failed('\tActive Gateway enabled incorrect')

        if int(details_inst_entry['dlrGatewayParams'][0]['precedence']) != \
                int(details_template['dlrGatewayParams'][0]['precedence']):
            self.failed('\tActive Gateway precedence incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_state_change_or_delete(self, title, device_transition_response, devices_id_dict, del_or_st):
    assert (type(title) == str), 'Title is not a string'
    assert type(device_transition_response) == dict, 'Devices Transition JSON not a dict'
    assert type(devices_id_dict) == dict, 'Devices ID Dictionary not a dict'

    log.info('\tCalling Verify Pass Or Fail for ' + str(del_or_st))

    device_transition_task_id = (json.dumps(device_transition_response['record']['taskId']))
    log.info('\tDevice ' + str(del_or_st) + ' Task ID: ' + str(device_transition_task_id))

    wait_for_task_completion(self.ind_info, device_transition_task_id)

    url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/tasks/' + str(device_transition_task_id) + '/subtasks'

    [subtasks_get_response, subtasks_get_json] = request_get(url, (self.username_in, self.password_in))
    assert (subtasks_get_response.status_code == 200 and subtasks_get_json['status'] == 200), 'GET Subtask response incorrect'
    number_of_subtasks = subtasks_get_json['recordCount']

    list_of_result = [subtasks_get_json['records'][recordIter]['resultStr'] for recordIter in range(0, number_of_subtasks)]
    list_of_details = [subtasks_get_json['records'][recordIter]['details'] for recordIter in range(0, number_of_subtasks)]
    list_of_subtask_id = [subtasks_get_json['records'][recordIter]['id'] for recordIter in range(0, number_of_subtasks)]

    log.info(pformat(devices_id_dict))

    for key in devices_id_dict:
        for i in range(0, number_of_subtasks):
            if (('[' + str(key) + ']') in str(list_of_details[i])) or \
                    (('[' + str(devices_id_dict[key][0]) + ']') in str(list_of_details[i])):
                if str(list_of_result[i]) != str(devices_id_dict[key][1]):
                    if str(title) == 'POSTdevicesstatechange':
                        self.failed('\tFailed To Transition Device to ' + str(self.param_in['new_state'] + '; Task ID: ' +
                                                                              str(device_transition_task_id) + ' Subtask ID:' +
                                                                              str(list_of_subtask_id[i])))

                    elif str(title) == 'DELETEdevices':
                        self.failed('\tFailed To Delete Device; Task ID: ' + str(device_transition_task_id) + ' Subtask ID:' +
                                    str(list_of_subtask_id[i]))
                    else:
                        self.failed('No matching h_method for verify_pass_or_fail_state_change_or_delete')

                else:
                    if str(title) == 'POSTdevicesstatechange' and str(list_of_result[i]) == 'Success':
                        log.info('\tTransitioned Device with IP ' + str(key) + ' to ' + str(self.param_in['new_state']) + ' state')

                    elif str(title) == 'DELETEdevices' and str(list_of_result[i]) == 'Success':
                        log.info('\tDeleted Device with IP ' + str(key))

                    elif (str(title) == 'POSTdevicesstatechange' or str(title) == 'DELETEdevices') and \
                            str(list_of_result[i]) == 'Error':
                        log.info('\t"Error" test case passed')

                    else:
                        self.failed('No matching h_method for verify_pass_or_fail_state_change_or_delete')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_node_summary(self, param_in_dict, dlr_result_json):
    log.info('\tCalling Verify Pass Or Fail for GET DLR Node Summary by ID')

    dlr_node_summary_json = dlr_result_json['dlr']

    if str(param_in_dict['empty']) == 'True' and len(dlr_node_summary_json) != 0:
        log.info(pformat(dlr_node_summary_json))
        self.failed('\tExpected empty DLR Node Summary record')

    if str(param_in_dict['empty']) == 'False' and len(dlr_node_summary_json) == 0:
        log.info(pformat(dlr_node_summary_json))
        self.failed('\tExpected non-zero DLR Node Summary record')

    if str(param_in_dict['empty']) == 'True' and len(dlr_node_summary_json) == 0:
        if str(param_in_dict['message']) != str(dlr_result_json['message']):
            log.info('\tExpected DLR Node Summary message: ' + str(param_in_dict['message']))
            log.info('\tActual DLR Node Summary message: ' + str(dlr_result_json['message']))
            self.failed('\tGET DLR Node Summary by ID result incorrect')

    if str(param_in_dict['empty']) == 'False':
        if 'dlr_node_summary_template' not in param_in_dict:
            self.failed('\tDLR Node Summary template missing')

        if str(param_in_dict['dlr_node_summary_template']) == 'null':
            if len(dlr_node_summary_json) == 0:
                self.failed('\tExpected non-zero DLR Node Summary record')
            return

        dlr_node_summary_json = dlr_node_summary_json[0]

        test_path = str((os.path.dirname(os.path.abspath(__file__))))
        node_summary_template = read_json_data(test_path + '/' + str(param_in_dict['dlr_node_summary_template']))

        verify_pass_or_fail_dlr_members(self, node_summary_template, dlr_node_summary_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_dlr_members(self,node_summary_template, dlr_node_summary_json):

    for field in dlr_node_summary_fields_list:
        if str(node_summary_template[field]) != str(dlr_node_summary_json[field]):
            log.info('\tExpected value for attribute: ' + str(field) + ' is: ' + str(node_summary_template[field]))
            log.info('\tValue for attribute: ' + str(field) + ' is: ' + str(dlr_node_summary_json[field]))
            self.failed('\tDLR Node Summary entry for attribute: ' + str(field) + ' incorrect')

    for item in node_summary_template['dlrMembers']:
        node_index = int(item['index'])

        node_json_entry = [dlr_node_summary_json['dlrMembers'][i] for i in range(0, len(dlr_node_summary_json['dlrMembers']))
                           if int(dlr_node_summary_json['dlrMembers'][i]['index']) == int(node_index)][0]

        for field in dlr_node_summary_members_fields_dict:
            if not dlr_node_summary_members_fields_dict[field]:
                if str(item[field]) != str(node_json_entry[field]):
                    log.info('\tExpected value for attribute: ' + str(field) + ' is: ' + str(item[field]))
                    log.info('\tValue for attribute: ' + str(field) + ' is: ' + str(node_json_entry[field]))
                    self.failed('\tDLR Node Summary entry for attribute: ' + str(field) + ' incorrect')

            else:
                for subfield in dlr_node_summary_members_fields_dict[field]:
                    if subfield == 'deviceId':
                        node_id = str(commons_retrieve_device_info_by_ip(self.ind_info, item[field][subfield], 'id', False))
                        if node_id == 'null':
                            self.failed('\tDevice with IP Address: ' + str(item[field][subfield]) + ' not in Inventory')

                        if int(node_json_entry[field][subfield]) != int(node_id):
                            log.info('\tExpected value for attribute: ' + str(subfield) + ' in section: ' +
                                     str(field) + 'is: ' + str(item[field][subfield]))
                            node_ip = str(commons_retrieve_device_info_by_id(self.ind_info, node_json_entry[field][subfield],
                                                                             'ipAddress', False))
                            node_name = str(commons_retrieve_device_info_by_id(self.ind_info, node_json_entry[field][subfield],
                                                                               'name', False))
                            log.info('\t' + str(field) + ' actual IP Address is: ' + str(node_ip))
                            log.info('\t' + str(field) + ' actual Name is: ' + str(node_name))
                            self.failed('\tDLR Node Summary entry for attribute: ' + str(subfield) + ' incorrect')

                    else:
                        if str(item[field][subfield]) != str(node_json_entry[field][subfield]):
                            log.info('\tExpected value for attribute: ' + str(subfield) + ' in section: ' +
                                     str(field) + ' is: ' + str(node_json_entry[field][subfield]))
                            log.info('\tActual value for attribute: ' + str(subfield) + ' in section: ' +
                                     str(field) + ' is: ' + str(node_json_entry[field][subfield]))
                            self.failed('\tDLR Node Summary entry for attribute: ' + str(subfield) + ' incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def wait_for_task_completion(ind_info, task_id):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    try:
        assert type(int(task_id)) == int
    except ValueError:
        log.info('\tInvalid Task ID: ' + str(task_id))
        return

    log.info('\tWaiting for Task ID: ' + str(task_id) + '...')
    while True:
        url = 'https://' + ind_info['ip'] + ':8443/api/v1/tasks/' + str(task_id)
        [tasks_get_response, tasks_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
        assert (tasks_get_response.status_code == 200 and tasks_get_json['status'] == 200), 'GET Tasks response incorrect'

        try:
            end_of_task = tasks_get_response.json()
        except:
            continue
        end_of_task_timestamp = (json.dumps(tasks_get_json['record']['endTimeStr']))
        if end_of_task_timestamp != 'null':
            break
        time.sleep(3)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def commons_retrieve_device_info_by_ip(ind_info, ip_address, device_info_parameter, return_json):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert (type(ip_address) == str and is_valid_ip(ip_address)), 'Invalid IP address'
    assert type(device_info_parameter) == str, 'Device information not a string'
    assert type(return_json) == bool, 'Return JSON option must be True or False'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices?searchString=ipAddress:"' + str(ip_address) + '"&direction=ASC'
    [device_get_response, device_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (device_get_response.status_code == 200 and device_get_json['status'] == 200), \
        'GET Devices response incorrect'

    if return_json:
        device_info = [device_get_json['records']]
    else:
        device_info = [device_get_json['records'][0][device_info_parameter]]

    if len(device_info) == 0:
        log.info('\tFailed to find Device: ' + str(ip_address))
        return 'null'

    return device_info[0]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def commons_retrieve_device_info_by_id(ind_info, id, device_info_parameter, return_json):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(id) == int, 'Invalid ID '
    assert type(device_info_parameter) == str, 'Device information not a string'
    assert type(return_json) == bool, 'Return JSON option must be True or False'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices?searchString=id:"' + str(id) + '"&direction=ASC'
    [device_get_response, device_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (device_get_response.status_code == 200 and device_get_json['status'] == 200), \
        'GET Devices response incorrect'

    if return_json:
        device_info = [device_get_json['records'][i]
                       for i in range(0, device_get_json['recordCount'])]
    else:
        device_info = [device_get_json['records'][i][device_info_parameter]
                       for i in range(0, device_get_json['recordCount'])]

    if len(device_info) == 0:
        log.info('\tFailed to find Device: ' + str(id))
        return 'null'

    return device_info[0]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))
