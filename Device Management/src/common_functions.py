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
import pexpect
from pprint import pformat
from functools import wraps
from pprint import pformat
from ats.topology import loader
from rest_functions import request_get, request_delete, request_post, request_put, request_get_file

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

other_device_protocols = [
    'CIP',
    'PROFINET',
    'SNMP',
    'Modbus',
    'BACnet',
    'OPC UA',
    'NetBIOS'
]

duplex_dict = {
    'full': 'Full-duplex',
    'half': 'Half-duplex',
    'auto': 'Auto-duplex'
}

speed_dict = {
    '10': '10Mb/s',
    '100': '100Mb/s',
    '1000': '1000Mb/s',
    'auto': 'Auto-speed'
}

# Master list of prompts to be handled on ssh ..
promptList = [ \
    'Username: ', \
    '(?<!shell\))> ?$', \
    '[Pp]assword: $', \
    '(?<!debug\))# ?$', \
    'Linux\(debug\)# $', \
    'switch\(shell\)> $', \
    'no route', \
    'not resolve', \
    'Connection refused', \
    'bash-[0-9].[0-9]# ?$', \
    pexpect.EOF, \
    pexpect.TIMEOUT, \
    '(config)#' \
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

    log.info('\tCalling Verify Pass Or Fail for GET by Parameter')

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

    passed = False
    for key in devices_id_dict:
        for i in range(0, number_of_subtasks):
            if (('[' + str(key) + ']') in str(list_of_details[i])) or \
                    (('[' + str(devices_id_dict[key][0]) + ']') in str(list_of_details[i])) or \
                    (('[' + str(devices_id_dict[key][2]) + ']') in str(list_of_details[i])):
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
                        passed = True

                    elif str(title) == 'DELETEdevices' and str(list_of_result[i]) == 'Success':
                        log.info('\tDeleted Device with IP ' + str(key))
                        passed = True

                    elif (str(title) == 'POSTdevicesstatechange' or str(title) == 'DELETEdevices') and \
                            str(list_of_result[i]) == 'Error':
                        log.info('\t"Error" test case passed')
                        passed = True

                    else:
                        self.failed('No matching h_method for verify_pass_or_fail_state_change_or_delete')

    if not passed:
        log.info('\tCheck the Task and Subtasks. No match for Device Names or IDs')
        if str(title) == 'POSTdevicesstatechange':
            self.failed('\tFailed To Transition Device to ' + str(self.param_in['new_state'] + '; Task ID: ' +
                                                                  str(device_transition_task_id)))

        elif str(title) == 'DELETEdevices':
            self.failed('\tFailed To Delete Device; Task ID: ' + str(device_transition_task_id) + ' Subtask ID:' +
                        str(list_of_subtask_id[i]))
        else:
            self.failed('No matching h_method for verify_pass_or_fail_state_change_or_delete')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_port_config_meta(self, ports_meta_get_json, empty_speed_ports):
    ports_w_sp_conf_dict = {}
    ports_wo_sp_config = []
    for i in range(0, len(ports_meta_get_json['record'])):
        for j in range(0, len(ports_meta_get_json['record'][i]['ports'])):
            if not ports_meta_get_json['record'][i]['ports'][j]['speedValues']:
                ports_wo_sp_config.append(ports_meta_get_json['record'][i]['ports'][j]['portName'])
            else:
                ports_w_sp_conf_dict[ports_meta_get_json['record'][i]['ports'][j]['portName']] = \
                    [sp_[0] for sp_ in ports_meta_get_json['record'][i]['ports'][j]['speedValues']]

    if empty_speed_ports == 'null':
        if len(ports_wo_sp_config) != 0:
            log.info(ports_wo_sp_config)
            self.failed('\tSome ports do not have speed config values')
    elif sorted(ports_wo_sp_config) != sorted(empty_speed_ports):
        log.info(sorted(ports_wo_sp_config))
        log.info(sorted(empty_speed_ports))
        self.failed('\tPorts without speed config values incorrect')

    for key in ports_w_sp_conf_dict:
        if ''.join([i for i in key.split('/')[0] if not i.isdigit()]) == 'FastEthernet':
            if sorted(ports_w_sp_conf_dict[key]) != sorted(['auto', '10', '100']):
                log.info(sorted(ports_w_sp_conf_dict[key]))
                self.failed('\tSpeed config values for port ' + str(key) + ' incorrect')
        elif ''.join([i for i in key.split('/')[0] if not i.isdigit()]) == 'GigabitEthernet':
            if sorted(ports_w_sp_conf_dict[key]) != sorted(['auto', '10', '100', '1000']):
                log.info(sorted(ports_w_sp_conf_dict[key]))
                self.failed('\tSpeed config values for port ' + str(key) + ' incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_port_config(self, port_config_post_json, device_id, port_id, ip_address, port_name, port_config_com,
                                    speed, access_vlan, shutdown_res, duplex):
    task_id = port_config_post_json['record']['taskId']
    result = wait_for_task_completion_port(self.ind_info, task_id)
    if self.expected_in[0] == 'Success':
        if not refresh_device(self, device_id):
            self.failed('\tDevice Refresh failed for: ' + str(ip_address))
        else:
            log.info('\tDevice Refresh Successful!')
            url_s = 'https://' + self.ind_info['ip'] + ':8443/api/v1/supported-devices/' + str(device_id) + '/ports-details?direction=ASC'
            [port_details_response, ports_details_json] = request_get(url_s, (self.ind_info['username'], self.ind_info['password']))
            assert (port_details_response.status_code == 200 and ports_details_json['status'] == 200), 'GET Ports response incorrect'

            if access_vlan != 'null':
                url_s = 'https://' + self.ind_info['ip'] + ':8443/api/v1/supported-devices/' + str(device_id) + '/vlans?direction=ASC'
                [vlan_details_response, vlan_details_json] = request_get(url_s, (self.ind_info['username'], self.ind_info['password']))
                assert (vlan_details_response.status_code == 200 and vlan_details_json['status'] == 200), 'GET Vlans response incorrect'

                ports_in_vlan = [vlan_details_json['records'][i]['switchPorts'] for i in range(0, vlan_details_json['recordCount'])
                                 if str(int(access_vlan)) == str(vlan_details_json['records'][i]['vlanId'])][0]

            port_info = [ports_details_json['records'][i] for i in range(0, ports_details_json['recordCount'])
                         if str(port_id) == str(ports_details_json['records'][i]['id'])][0]

            log.info('\tTesting configured values')
            for com in port_config_com:
                if 'speed' in com:
                    if str(port_info['speed']) != str(speed_dict[speed]):
                        log.info(str(port_info['speed']))
                        log.info(str(speed_dict[speed]))
                        self.failed('\tConfigured speed value incorrect')

                if 'shutdown' in com:
                    if str(port_info['adminState']) != str(shutdown_res):
                        log.info(str(port_info['adminState']))
                        log.info(str(shutdown_res))
                        self.failed('\tConfigured shutdown value incorrect')

                if 'accessVlan' in com:
                    if port_name not in ports_in_vlan:
                        log.info(port_name)
                        log.info(ports_in_vlan)
                        log.info(pformat(vlan_details_json))
                        self.failed('\tConfigured Access Vlan value incorrect')

                if 'duplex' in com:
                    if str(port_info['duplex']) != str(duplex_dict[duplex]):
                        log.info(str(port_info['duplex']))
                        log.info(str(duplex_dict[duplex]))
                        self.failed('\tConfigured Duplex value incorrect')

    elif self.expected_in[0] == 'Error':
        log.info('\t"Failed" task result is: ' + str(result))
        if result[0] != 'Failed':
            self.failed('\tPort configration task result incorrect')
        log.info('\t"Error" test case passed')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def verify_pass_or_fail_backplane(self, title, backplane_post_response):
    assert (type(title) == str), 'Title is not a string'
    assert type(backplane_post_response) == dict, 'Devices Transition JSON not a dict'

    log.info('\tCalling Verify Pass Or Fail for Backplane Bridging task')

    device_transition_task_id = (json.dumps(backplane_post_response['record']['taskId']))
    log.info('\tDevice Backplane; Task ID: ' + str(device_transition_task_id))

    wait_for_task_completion(self.ind_info, device_transition_task_id)

    url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/tasks/' + str(device_transition_task_id) + '/subtasks'

    [subtasks_get_response, subtasks_get_json] = request_get(url, (self.username_in, self.password_in))
    assert (subtasks_get_response.status_code == 200 and subtasks_get_json['status'] == 200), 'GET Subtask response incorrect'

    if 'Backplane Discovery Result: \r\nCIP port with IP ' + str(self.param_in['ip_address']) + \
           ' is the entry port for this backplane' not in subtasks_get_json['records'][0]['details']:
        self.failed('\tBackplane Task ' + str(device_transition_task_id) + ' failed')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def create_port_config_request(speed, access_vlan, shutdown, duplex):
    port_config_com_2 = [{'speed': str(speed)}, {'accessVlan': str(access_vlan)}, {'shutdown': str(shutdown)}, {'duplex': str(duplex)}]

    port_config_com = []
    for i in range(0, len(port_config_com_2)):
        if 'speed' in port_config_com_2[i]:
            if port_config_com_2[i]['speed'] == 'null':
                pass
            else:
                port_config_com.append({'speed': 'temp'})
                port_config_com[-1]['speed'] = str(port_config_com_2[i]['speed'])
        elif 'accessVlan' in port_config_com_2[i]:
            if port_config_com_2[i]['accessVlan'] == 'null':
                pass
            else:
                port_config_com.append({'accessVlan': 'temp'})
                port_config_com[-1]['accessVlan'] = int(port_config_com_2[i]['accessVlan'])
        elif 'shutdown' in port_config_com_2[i]:
            if port_config_com_2[i]['shutdown'] == 'null':
                pass
            else:
                port_config_com.append({'shutdown': 'temp'})
                port_config_com[-1]['shutdown'] = True if port_config_com_2[i]['shutdown'] == 'True' else False
        elif 'duplex' in port_config_com_2[i]:
            if port_config_com_2[i]['duplex'] == 'null':
                pass
            else:
                port_config_com.append({'duplex': 'temp'})
                port_config_com[-1]['duplex'] = str(port_config_com_2[i]['duplex'])

    return port_config_com


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def connect_to_device(ipAddr, uname, pwd, func):
    assert type(uname) == str, 'Username not a string'
    assert type(pwd) == str, 'Password is not a string'
    assert type(func) == str, 'Coonect to Device function is not a string'

    if type(ipAddr) == list:
        ipAddress = ipAddr
    else:
        ipAddress = [ipAddr]

    username = uname
    password = pwd

    for ip in ipAddress:
        assert is_valid_ip(ip), 'Invalid IP address'
        cmd = 'telnet {0}'.format(ip)
        log.info('###################################################################################################')
        log.info(cmd)
        hdl = pexpect.spawn(cmd, timeout=20)

        done = False
        error = False
        while not done:
            i = hdl.expect(promptList, timeout=20)
            log.info(i)
            log.info(hdl.before)
            if i == 0:
                # login:
                hdl.sendline(username)
            elif i == 1:
                # Enable prompt needed for IOS devices
                hdl.sendline('enable')
            elif i == 2:
                # Got Password prompt .. send password
                hdl.sendline(password)
            elif i == 3:
                # Got final switch prompt, ready to launch commands
                done = True
            elif i == 4:
                # Linux prompt
                hdl.sendline('exit')
            elif i == 5:
                # bash shell
                hdl.sendline('exit')
            elif i == 6:
                # No route to the destination switch
                log.info('No route to the destination switch ..')
                # log.error('No route to the destination switch ..')
                hdl.terminate(force=True)
                error = True
                done = True
            elif i == 7:
                # Not able to resolve IP for the switch
                log.info('Not able to resolve the DNS name of the host ..')
                # log.error('Not able to resolve the DNS name of the host ..')
                hdl.terminate(force=True)
                error = True
                done = True
            elif i == 8:
                # Connection refused
                log.info('Connection refused by {0}..'.format(ip))
                # log.error('Connection refused by IP {0}..'.format(ipAddress))
                hdl.terminate(force=True)
                error = True
                done = True
            elif i == 9:
                # bash-4.2 prompt. Typically seen at bootup failure
                log.info('Got bash prompt. Switch failed to boot properly')
                # log.error('Got bash prompt. Switch failed to boot properly')
                hdl.sendline('reboot')
                hdl.terminate(force=True)
                error = True
                done = True
            elif i == 10:
                # EOF
                log.info('Connection failed to {0}'.format(ip))
                # log.error('Connection failed to IP {0}..'.format(ipAddress))
                hdl.terminate(force=True)
                error = True
                done = True
            elif i == 11:
                # TIMEOUT
                log.info('Did not receive any expected prompts')
                # log.error('Did not receive any expected prompts')
                hdl.terminate(force=True)
                error = True
                done = True
            elif i == 12:
                # config
                log.info('configue mode detected')
                done = True
        if error:
            continue

        if 'privilege' in func:
            change_privilege_mode(hdl, re.findall(r'\d+', func)[0], uname, pwd)

        if func == 'nms_odm':
            delete_nms_odm(hdl)

        log.info('###################################################################################################')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def change_privilege_mode(hdl, privilege, uname, pwd):

    try:
        priv = int(privilege)
    except Exception as msg:
        assert False, 'Privilege mode is not an integer'

    hdl.sendline("conf t")
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)
    hdl.sendline("username " + str(uname) + " privilege " + str(priv) + " password 0 " + str(pwd))
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)
    hdl.sendline("end")
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)
    hdl.sendline("wr")
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_nms_odm(hdl):

    hdl.sendline("delete flash:nms.odm")
    hdl.sendline("")
    hdl.sendline("")
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)
    hdl.sendline("")
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)
    hdl.sendline("")
    temp = hdl.expect('#', timeout=10)
    log.info(hdl.before)


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
def wait_for_task_completion_port(ind_info, task_id):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    try:
        assert type(int(task_id)) == int
    except ValueError:
        log.info('Invalid Task ID: ' + str(task_id))
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
        time.sleep(2)

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/tasks/' + str(task_id) + '/subtasks'
    [tasks_get_response, tasks_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    return [tasks_get_json['records'][0]['stateStr'], tasks_get_json['records'][0]['details']]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def refresh_device(self, dev_id):
    counter = 4

    while True:
        url_s = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices/' + str(dev_id) + '/refresh/tasks'
        [devices_refresh_post_response, devices_refresh_post_json] = request_post(url_s, (self.ind_info['username'],
                                                                                          self.ind_info['password']),
                                                                                  {"action": "deviceRefresh"})
        assert (devices_refresh_post_response.status_code == 200 and devices_refresh_post_json['status'] == 200), \
            'POST Devices Refresh response incorrect'
        counter -= 1

        task_id = devices_refresh_post_json['record']['taskId']
        result = wait_for_task_completion_port(self.ind_info, task_id)

        if result[0] != 'Completed' and counter == 1:
            return False
        elif result[0] != 'Completed' and counter > 1:
            time.sleep(20)
            continue
        elif result[0] == 'Completed':
            return True