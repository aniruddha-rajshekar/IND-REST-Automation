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

ptp_node_summary_fields_dict = {
    'id': [],
    'slot': [],
    'stepsRemoved': [],
    'role': [],
    'ptpMasterLink': [
        'deviceId',
        'deviceName',
        'deviceType',
        'protocol',
        'portName'
    ],
    'ptpGrandMasterLink': [
        'deviceId',
        'deviceName',
        'deviceType',
        'protocol',
        'portName',
    ]
}

ptp_port_fields_list = [
    'portNumber',
    'portState',
    'portName',
]

ptp_domain_summary_fields_dict = {
    'ptpDeviceLink': [
        'deviceId',
        'deviceName',
        'deviceType',
        'protocol',
        'portName',
        'deviceCategoryStr',
    ],
    'role': [],
    'bmcaRank': [],
    'productId': [],
    'priority1': [],
    'priority2': []
}

ptp_gm_offset_fields_list = [
    'id',
    'cipSlot',
    'clockType',
    'offsetThresholdAtGrandMasterInNanoSeconds',
    'ptpDomainNumber',
]


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
def verify_pass_or_fail_ptp_domain_summary(self, param_in_dict, ptp_domain_json):
    assert type(ptp_domain_json) == dict, 'PTP Domain Summary JSON not a dict'

    log.info('\tCalling Verify Pass Or Fail for GET PTP Domain Summary by ID')

    if 'domain_template' not in param_in_dict:
        self.failed('\tPTP Domain template missing')

    test_path = str((os.path.dirname(os.path.abspath(__file__))))
    domain_template = read_json_data(test_path + '/' + str(param_in_dict['domain_template']))

    if str(domain_template['ptpDomainNumber']) != str(ptp_domain_json['ptpDomainNumber']):
        log.info('\tExpected PTP Domain Number: ' + str(domain_template['ptpDomainNumber']))
        log.info('\tActual PTP Domain Number: ' + str(ptp_domain_json['ptpDomainNumber']))
        self.failed('\tPTP Domain Number incorrect')

    for item in domain_template['ptpDomainDevicesVo']:
        node_rank = int(item['bmcaRank'])

        node_json_entry = [ptp_domain_json['ptpDomainDevicesVo'][i] for i in range(0, len(ptp_domain_json['ptpDomainDevicesVo']))
                           if int(ptp_domain_json['ptpDomainDevicesVo'][i]['bmcaRank']) == int(node_rank)][0]

        for field in ptp_domain_summary_fields_dict:
            if not ptp_domain_summary_fields_dict[field]:
                if str(item[field]) != str(node_json_entry[field]):
                    log.info('\tExpected value for attribute: ' + str(field) + ' is: ' + str(item[field]))
                    log.info('\tValue for attribute: ' + str(field) + ' is: ' + str(node_json_entry[field]))
                    self.failed('\tPTP Domain Summary entry for attribute: ' + str(field) + ' incorrect')

            else:
                for subfield in ptp_domain_summary_fields_dict[field]:
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
                            self.failed('\tPTP Domain Summary entry for attribute: ' + str(subfield) + ' incorrect')

                    else:
                        if str(item[field][subfield]) != str(node_json_entry[field][subfield]):
                            log.info('\tExpected value for attribute: ' + str(subfield) + ' in section: ' +
                                     str(field) + ' is: ' + str(node_json_entry[field][subfield]))
                            log.info('\tActual value for attribute: ' + str(subfield) + ' in section: ' +
                                     str(field) + ' is: ' + str(node_json_entry[field][subfield]))
                            self.failed('\tPTP Domain Summary entry for attribute: ' + str(subfield) + ' incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_ptp_topology(self, param_in_dict, ptp_topology_json):
    log.info('\tCalling Verify Pass Or Fail for GET PTP Topology by Group')

    if 'topology_template' not in param_in_dict:
        self.failed('\tPTP Topology template missing')

    test_path = str((os.path.dirname(os.path.abspath(__file__))))
    topology_template = read_json_data(test_path + '/' + str(param_in_dict['topology_template']))

    for item in topology_template:
        node_ip = item['ipAddress']
        node_slot = item['slot']
        node_id = str(commons_retrieve_device_info_by_ip(self.ind_info, node_ip, 'id', False))

        if node_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(node_ip) + ' not in Inventory')

        node_ip_entry = [ptp_topology_json[i] for i in range(0, len(ptp_topology_json))
                         if (int(ptp_topology_json[i]['id']) == int(node_id)
                             and str(node_slot) == str(ptp_topology_json[i]['slot']))][0]

        log.info('\tPTP Node entry in GET PTP Topology by Group Result:')
        log.info(pformat(node_ip_entry))

        if str(node_slot) != str(node_ip_entry['slot']):
            self.failed('\tPTP Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' slot incorrect')

        if str(item['role']) != str(node_ip_entry['role']):
            self.failed('\tPTP Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' role incorrect')

        child_id_list = []
        for i in range(0, len(item['childNodes'])):
            child_id = str(commons_retrieve_device_info_by_ip(self.ind_info, item['childNodes'][i], 'id', False))
            if child_id == 'null':
                self.failed('\tDevice with IP Address: ' + str(item['childNodes'][i]) + ' not in Inventory')
            child_id_list.append(int(child_id))

        if sorted(child_id_list) != sorted(node_ip_entry['childNodes']):
            self.failed('\tPTP Node with IP Address: ' + str(node_ip) + ' and ID: ' + str(node_id) + ' child nodes incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_ptp_node_summary(self, param_in_dict, ptp_summary_json):
    log.info('\tCalling Verify Pass Or Fail for GET PTP Node Summary by ID')

    if str(param_in_dict['is_ptp']) == 'False':
        if str(ptp_summary_json['message']) != 'PTP not supported for this device.':
            log.info('\tPTP Node Summary message for non-PTP device is: ' + str(ptp_summary_json['message']))
            self.failed('\tPTP Node Summary message for non-PTP device incorrect')

    if str(param_in_dict['is_ptp']) == 'True':
        if 'ptp_summary_template' not in param_in_dict:
            self.failed('\tPTP Node Summary template missing')

        test_path = str((os.path.dirname(os.path.abspath(__file__))))
        if str(param_in_dict['ptp_summary_template']) != 'null':
            summary_template = read_json_data(test_path + '/' + str(param_in_dict['ptp_summary_template']))
        else:
            return

        if 'slot_val' in param_in_dict:
            summary_inst_entry = [ptp_summary_json[i] for i in range(0, len(ptp_summary_json))
                                  if (int(ptp_summary_json[i]['slot']) == int(param_in_dict['slot_val']) and
                                      str(ptp_summary_json[i]['role']) == str(param_in_dict['clockType']))][0]
        else:
            summary_inst_entry = [ptp_summary_json[i] for i in range(0, len(ptp_summary_json))
                                  if str(ptp_summary_json[i]['role']) == str(param_in_dict['clockType'])][0]

        log.info('\tPTP Summary Instance entry in GET PTP Node Summary by ID Result:')
        log.info(pformat(summary_inst_entry))

        verify_pass_or_fail_ptp_main_node_summary(self, summary_template, summary_inst_entry)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_ptp_main_node_summary(self, summary_template, summary_inst_entry):
    for field in ptp_node_summary_fields_dict:
        if not ptp_node_summary_fields_dict[field]:
            if field == 'id':
                node_id = str(commons_retrieve_device_info_by_ip(self.ind_info, summary_template[field], 'id', False))
                if node_id == 'null':
                    self.failed('\tDevice with IP Address: ' + str(summary_template[field]) + ' not in Inventory')

                if int(summary_inst_entry[field]) != int(node_id):
                    log.info('\tExpected value for attribute: ' + str(field) + 'is: ' + str(summary_template[field]))
                    node_ip = str(commons_retrieve_device_info_by_id(self.ind_info, summary_inst_entry[field],
                                                                     'ipAddress', False))
                    node_name = str(commons_retrieve_device_info_by_id(self.ind_info, summary_inst_entry[field],
                                                                       'name', False))
                    log.info('\t' + str(field) + ' actual IP Address is: ' + str(node_ip))
                    log.info('\t' + str(field) + ' actual Name is: ' + str(node_name))
                    self.failed('\tPTP Node Summary entry for attribute: ' + str(field) + ' incorrect')
            else:
                if str(summary_template[field]) != str(summary_inst_entry[field]):
                    log.info('\tExpected value for attribute: ' + str(field) + ' is: ' + str(summary_template[field]))
                    log.info('\tActual value for attribute: ' + str(field) + ' is: ' + str(summary_inst_entry[field]))
                    self.failed('\tPTP  Node Summary entry for attribute: ' + str(field) + ' incorrect')
        else:
            for subfield in ptp_node_summary_fields_dict[field]:
                if subfield == 'deviceId':
                    node_id = str(commons_retrieve_device_info_by_ip(self.ind_info, summary_template[field][subfield], 'id', False))
                    if node_id == 'null':
                        self.failed('\tDevice with IP Address: ' + str(summary_template[field][subfield]) + ' not in Inventory')

                    if int(summary_inst_entry[field][subfield]) != int(node_id):
                        log.info('\tExpected value for attribute: ' + str(subfield) + ' in section: ' +
                                 str(field) + 'is: ' + str(summary_template[field][subfield]))
                        node_ip = str(commons_retrieve_device_info_by_id(self.ind_info, summary_inst_entry[field][subfield],
                                                                         'ipAddress', False))
                        node_name = str(commons_retrieve_device_info_by_id(self.ind_info, summary_inst_entry[field][subfield],
                                                                           'name', False))
                        log.info('\t' + str(field) + ' actual IP Address is: ' + str(node_ip))
                        log.info('\t' + str(field) + ' actual Name is: ' + str(node_name))
                        self.failed('\tPTP Node Summary entry for attribute: ' + str(subfield) + ' incorrect')
                else:
                    if str(summary_template[field][subfield]) != str(summary_inst_entry[field][subfield]):
                        log.info('\tExpected value for attribute: ' + str(subfield) + ' in section: ' +
                                 str(field) + ' is: ' + str(summary_template[field][subfield]))
                        log.info('\tActual value for attribute: ' + str(subfield) + ' in section: ' +
                                 str(field) + ' is: ' + str(summary_inst_entry[field][subfield]))
                        self.failed('\tPTP Node Summary entry for attribute: ' + str(subfield) + ' incorrect')

    log.info('\tTesting PTP ports information')
    for i in range(0, len(summary_inst_entry['portStates'])):
        for field in ptp_port_fields_list:
            if str(summary_template['portStates'][i][field]) != str(summary_inst_entry['portStates'][i][field]):
                log.info('\tExpected value for attribute: ' + str(field) + ' is: ' + str(summary_template['portStates'][i][field]))
                log.info('\tActual value for attribute: ' + str(field) + ' is: ' + str(summary_inst_entry['portStates'][i][field]))
                self.failed('\tPTP Node Summary entry for attribute: ' + str(field) + 'and portNumber: ' +
                            str(str(summary_inst_entry['portStates'][i]['portNumber']) + ' incorrect'))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_ptp_gm_offset_threshold(self, param_in_dict, ptp_offset_json, device_id):
    assert type(ptp_offset_json) == dict, 'PTP GM Offset Threshold JSON not a dict'
    assert type(device_id) == int, 'Invalid Device ID type'

    log.info('\tCalling Verify Pass Or Fail for GET PTP Node Summary by ID')

    ptp_gm_offset_result_dict = {}

    url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices/' + str(device_id) + '/ptp'
    [ptp_instances_get_response, ptp_instances_get_json] = request_get(url, (self.ind_info['username'], self.ind_info['password']))
    assert (ptp_instances_get_response.status_code == 200 and ptp_instances_get_json['status'] == 200), \
        'GET PTP Instances response incorrect'

    if 'cip_slot' in param_in_dict:
        ptp_offset_record = [ptp_instances_get_json['records'][i] for i in range(0, ptp_instances_get_json['recordCount'])
                             if str(ptp_instances_get_json['records'][i]['cipSlot']) == str(param_in_dict['cip_slot'])][0]
    else:
        ptp_offset_record = [ptp_instances_get_json['records'][i] for i in range(0, ptp_instances_get_json['recordCount'])][0]

    for field in ptp_gm_offset_fields_list:
        if field == 'offsetThresholdAtGrandMasterInNanoSeconds':
            if str(param_in_dict['gm_offset_threshold']) == '0':
                ptp_gm_offset_result_dict[field] = str('None')
            else:
                ptp_gm_offset_result_dict[field] = str(param_in_dict['gm_offset_threshold'])
            continue

        ptp_gm_offset_result_dict[field] = str(ptp_offset_record[field])

    for field in ptp_gm_offset_fields_list:
        if str(ptp_gm_offset_result_dict[field]) != str(ptp_offset_json[field]):
            log.info('\tExpected value for attribute: ' + str(field) + ' is: ' + str(ptp_gm_offset_result_dict[field]))
            log.info('\tActual value for attribute: ' + str(field) + ' is: ' + str(ptp_offset_json[field]))
            self.failed('\tPTP GM Offset Threshold result for attribute: ' + str(field) + ' incorrect')


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
        device_info = [device_get_json['records'][i]
                       for i in range(0, device_get_json['recordCount'])]
    else:
        device_info = [device_get_json['records'][i][device_info_parameter]
                       for i in range(0, device_get_json['recordCount'])]

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
