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

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)

from rest_functions import request_get, request_delete, request_post, request_put

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

other_device_protocols = [
    'CIP',
    'PROFINET',
    'SNMP',
    'MODBUS',
    'BACNET',
]

request_headers = {'Content-Type': 'application/json'}


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
def verify_pass_or_fail_vlans(self, param_in_dict, vlans_get_json):
    assert type(param_in_dict) == dict, 'Parameters In is not a dictionary'
    assert type(vlans_get_json) == dict, 'GET Vlan JSON is not a dictionary'

    if 'listed_vlans' not in param_in_dict:
        self.failed('\tList of expected Vlans missing')

    if param_in_dict['listed_vlans'] == 'null':
        if len(vlans_get_json['records']) != 0:
            self.failed('\tList of Vlans is supposed to be empty')
    else:
        vlan_list = param_in_dict['listed_vlans']
        if type(vlan_list) is not list:
            vlan_list = [vlan_list]
        if not set(sorted(vlan_list)).issubset(set(sorted([str(item['id']) for item in vlans_get_json['records']]))):
            if self.expected_in[0] != 'Success':
                log.info('\t"Error" test case passed')
            else:
                log.info(set(sorted([str(item['id']) for item in vlans_get_json['records']])))
                self.failed('\tList of Vlans in group incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_topology_vlans(self, param_in_dict, topo_vlans_get_json, vlan_ids):
    if self.expected_in[0] == 'Empty':
        if len(topo_vlans_get_json['records']) != 0:
            self.failed('\tList of Topology Vlan Links is supposed to be empty')

    elif self.expected_in[0] == 'Success':
        if 'overlay_link_count' not in param_in_dict:
            self.failed('\tVlan Overlay expected links count missing')

        if param_in_dict['overlay_link_count'] != 'null':
            overlay_links_count = param_in_dict['overlay_link_count']
            if type(overlay_links_count) is not list:
                overlay_links_count = [overlay_links_count]

        for i_ in range(0, len(vlan_ids)):
            log.info('\tTesting links for VLAN: ' + str(vlan_ids[i_]))
            overlay_record = [topo_vlans_get_json['records'][i] for i in range(0, topo_vlans_get_json['recordCount'])
                              if str(topo_vlans_get_json['records'][i]['vlanId']) == str(vlan_ids[i_])]

            if str(overlay_links_count[i_]) == '0':
                if len(overlay_record) != 0:
                    log.info(overlay_record)
                    self.failed('\tVlan Overlay links obtained for non-existent Vlan')
                else:
                    continue

            overlay_record = overlay_record[0]
            if ':' in str(overlay_links_count[i_]):
                overlay_sub = str(overlay_links_count[i_]).split(':')
                overlay_sub = [str(i) for i in overlay_sub]
                if str(len(overlay_record['links'])) not in overlay_sub:
                    log.info('\tActual links count: ' + str(len(overlay_record['links'])))
                    log.info('\tExpected links count: ' + str(overlay_links_count[i_]))
                    self.failed('\tVlan Overlay links count incorrect')
            else:
                if str(len(overlay_record['links'])) != str(overlay_links_count[i_]):
                    log.info('\tActual links count: ' + str(len(overlay_record['links'])))
                    log.info('\tExpected links count: ' + str(overlay_links_count[i_]))
                    self.failed('\tVlan Overlay links count incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def connect_to_device(self, param_in, device_param):
    log.info('\t#####################################################################################')
    log.info('\t# Connect to the device to verify the information pulled by IND')
    log.info('\t# IOS COMMANDS Used and device info\n     ' + str(param_in))
    log.info('\t#                                                                                   #')
    log.info('\t#####################################################################################')
    testbed = loader.load(param_in['Devices'])
    for device in testbed:
        device.name = device_param['DeviceName']
        device.connections.a.ip = device_param['ip']

    current_system_info_raw = []
    for device in testbed:
        device.connect()
        for i in range(len(param_in['command'])):
            command_result = device.config(str(param_in['command'][i]))
            command_result = command_result.split('\n')

            command_result.pop(0)

            command_result.pop(len(command_result) - 1)

            command_result.pop(len(command_result) - 1)

            command_result_string = ''
            for item in command_result:
                command_result_string += item

            current_system_info_raw.append(command_result_string)
        device.disconnect()
    return current_system_info_raw


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
        assert (tasks_get_response.status_code == 200 and tasks_get_json['status'] == 200), 'GET Task response incorrect'

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
def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))
