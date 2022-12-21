from common_functions import *
from device_management_functions import *
from getALL import generateEvents

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_port_config_device_id(self, param_in_dict, ip_address, port_name):
    device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
    if device_id == 'null':
        device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        port_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
    else:
        device_id = int(device_id)
        if 'licensed_state' in param_in_dict:
            if param_in_dict['licensed_state'] == 'True':
                log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                change_state(self.ind_info, [device_id], 'Licensed')
                time.sleep(40)
        port_id = str(retrieve_supported_device_port_info_by_ip(self.ind_info, port_name, device_id, 'id', False))
        if port_id == 'null':
            port_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            port_id = int(port_id)

    return [device_id, port_id]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def post_on_demand_refresh(self, param_in_dict):
    log.info('\tPerforming POST Devices Refresh')
    is_valid_device = True

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevice IP Address missing')
    if 'device_state' not in param_in_dict:
        self.failed('\tDevice State Address missing')
    if 'active_operation' not in param_in_dict:
        self.failed('\tDevice Active Operation Address missing')

    ip_address = param_in_dict['ip_address']
    log.info('\tIP Address for POST Devices Refresh: ' + str(ip_address))

    if str(self.expected_in[0]) == '400' and not is_valid_ip(ip_address):
        device_id = str(ip_address)
    else:
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
            is_valid_device = False
        else:
            device_id = int(device_id)

        log.info('\tDevice ID for POST Devices Refresh: ' + str(device_id))

        param_in_dict['old_state'] = param_in_dict['device_state']
        if is_valid_device:
            perform_device_transition(self, [device_id])
            time.sleep(40)

            if str(param_in_dict['active_operation']) != 'null':
                if str(param_in_dict['active_operation']) == 'OnDemandRefresh':
                    url = self.url_path + '/' + str(device_id) + '/refresh/tasks'
                    [devices_refresh_post_response, devices_refresh_post_json] = request_post(url,
                                                                                              (self.username_in, self.password_in), {})
                    assert (devices_refresh_post_response.status_code == 200 and devices_refresh_post_json['status'] == 200), \
                        'POST On Demand Refresh response incorrect'
                    time.sleep(0.5)

    url = self.url_path + '/' + str(device_id) + '/refresh/tasks'
    [devices_refresh_post_response, devices_refresh_post_json] = request_post(url, (self.username_in, self.password_in),
                                                                              {"action": "deviceRefresh"})

    log.info('\tPrinting POST On Demand Device Refresh Result')
    log.info(pformat(devices_refresh_post_json))
    log.info('\tStatus Code: ' + str(devices_refresh_post_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, devices_refresh_post_json['status'], self.expected_in[0])
        return
    verify_pass_or_fail_status_code(self, self.h_method, devices_refresh_post_json['status'], '200')
    wait_for_task_completion(self.ind_info, json.dumps(devices_refresh_post_json['record']['taskId']))

    url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/tasks/' + str(json.dumps(devices_refresh_post_json['record']['taskId'])) + \
          '/subtasks'
    [subtasks_get_response, subtasks_get_json] = request_get(url, (self.username_in, self.password_in))
    assert (subtasks_get_response.status_code == 200 and subtasks_get_json['status'] == 200), 'GET Subtask response incorrect'

    log.info(str(subtasks_get_json['records'][0]['resultStr']))
    if str(subtasks_get_json['records'][0]['resultStr']) != str(self.expected_in[0]):
        self.failed('\tResult of POST Devices Refresh Task for Device with IP: ' + str(ip_address) +
                    ' does not match Expected value')
    else:
        log.info('\tPOST Devices Refresh Task for Device with IP: ' + str(ip_address) + ' complete')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_supported_devices_by_parameter(self, param_in_dict):
    log.info('\tPerforming GET All Supported Devices by Parameter')
    limit_val = 2147483640
    offset_val = 0
    field_val = 'supportedDevice.name'
    direction_val = 'ASC'

    if 'limit' not in param_in_dict:
        self.failed('\tLimit value missing')
    if 'offset' not in param_in_dict:
        self.failed('\tOffset value missing')
    if 'field' not in param_in_dict:
        self.failed('\tField value missing')
    if 'direction' not in param_in_dict:
        self.failed('\tDirection value missing')

    if param_in_dict['limit'] != 'null':
        limit_val = param_in_dict['limit']
    if param_in_dict['offset'] != 'null':
        offset_val = param_in_dict['offset']
    if param_in_dict['field'] != 'null':
        field_val = param_in_dict['field']
    if param_in_dict['direction'] != 'null':
        direction_val = param_in_dict['direction']

    url = self.url_path + '?limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + \
          '&direction=' + str(direction_val)
    log.info('\tGET All Supported Devices by Parameter URL: ' + str(url))

    [supported_get_response, supported_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET All Supported Devices by Parameter Result')
    log.info(pformat(supported_get_json))
    log.info('\tStatus Code: ' + str(supported_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, supported_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, supported_get_json['status'], '200')
        verify_pass_or_fail_get_all(self, self.h_method, supported_get_json['status'], self.expected_in[0], supported_get_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_supported_device_by_id(self, param_in_dict):
    log.info('\tPerforming GET Supported Device By ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tSupported Device IP Address missing')

    ip_address = param_in_dict['ip_address']
    log.info('\tIP Address for GET Supported Device by ID: ' + str(ip_address))

    if str(self.expected_in[0]) == '400':
        supported_device_id = str(ip_address)
    else:
        supported_device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if supported_device_id == 'null':
            supported_device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            supported_device_id = int(supported_device_id)

    log.info('\tSupported Device ID for GET Supported Device by ID: ' + str(supported_device_id))

    url = self.url_path + '/' + str(supported_device_id)
    [supported_id_get_response, supported_id_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Supported Device By ID Result')
    log.info(pformat(supported_id_get_json))
    log.info('\tStatus Code: ' + str(supported_id_get_json['status']))

    time.sleep(0.5)
    verify_pass_or_fail_status_code(self, self.h_method, supported_id_get_json['status'], self.expected_in[0])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_device_port_config_meta_by_id(self, param_in_dict):
    log.info('\tPerforming GET Device Port Config Meta By ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevice IP Address missing')

    if 'empty_speed_ports' not in param_in_dict:
        self.failed('\tList of empty Speed Ports missing')
    if param_in_dict['empty_speed_ports'] != 'null':
        empty_speed_ports = param_in_dict['empty_speed_ports']
        if type(empty_speed_ports) != list:
            empty_speed_ports = [empty_speed_ports]
    elif param_in_dict['empty_speed_ports'] == 'null':
        empty_speed_ports = 'null'

    ip_address = param_in_dict['ip_address']
    log.info('\tIP Address for GET Device Port Config Meta by ID: ' + str(ip_address))

    if str(self.expected_in[0]) == '400':
        device_id = str(ip_address)
    else:
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            device_id = int(device_id)

    log.info('\tDevice ID for GET Device Port Config Meta by ID: ' + str(device_id))
    if str(self.expected_in[0]) == '200':
        log.info('\tMoving Device ' + str(ip_address) + ' to Licensed state')
        change_state(self.ind_info, [device_id], 'Licensed')
        time.sleep(40)

    url = self.url_path + '/' + str(device_id) + '/ports-config-meta'
    [ports_meta_get_response, ports_meta_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Device Port Config Meta by ID Result')
    log.info(pformat(ports_meta_get_json))
    log.info('\tStatus Code: ' + str(ports_meta_get_json['status']))

    time.sleep(0.5)
    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, ports_meta_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, ports_meta_get_json['status'], '200')
        verify_pass_or_fail_port_config_meta(self, ports_meta_get_json, empty_speed_ports)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def post_device_port_config(self, param_in_dict):
    log.info('\tPerforming POST Device Port Config')

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevice IP Address missing')
    if 'port_name' not in param_in_dict:
        self.failed('\tDevice Port Name missing')

    if 'speed' not in param_in_dict:
        self.failed('\tSpeed value missing')
    if 'access_vlan' not in param_in_dict:
        self.failed('\tAccess Vlan value missing')
    if 'shutdown' not in param_in_dict:
        self.failed('\tShutdown value missing')
    if 'duplex' not in param_in_dict:
        self.failed('\tDuplex value missing')

    speed = param_in_dict['speed']
    access_vlan = param_in_dict['access_vlan']
    shutdown = param_in_dict['shutdown']
    duplex = param_in_dict['duplex']

    shutdown_res = 'null'
    if shutdown == 'True':
        shutdown_res = 'administratively down'
    elif shutdown == 'False':
        shutdown_res = 'down'

    ip_address = param_in_dict['ip_address']
    port_name = param_in_dict['port_name']
    log.info('\tIP Address for POST Device Port Config: ' + str(ip_address))
    log.info('\tPort Name for POST Device Port Config: ' + str(port_name))

    if str(self.expected_in[0]) == '400':
        if param_in_dict['licensed_state'] == 'True':
            [device_id, port_id] = get_port_config_device_id(self, param_in_dict, ip_address, port_name)
        else:
            device_id = str(ip_address)
            port_id = str(port_name)
    else:
        [device_id, port_id] = get_port_config_device_id(self, param_in_dict, ip_address, port_name)

    log.info('\tDevice ID for POST Device Port Config: ' + str(device_id))
    log.info('\tPort ID for POST Device Port Config: ' + str(port_id))
    port_config_com = create_port_config_request(speed, access_vlan, shutdown, duplex)
    log.info('\tPrinting POST Device Port Config Request')
    log.info(pformat(port_config_com))

    url = self.url_path + '/' + str(device_id) + '/ports/' + str(port_id) + '/config'
    log.info('\tPOST Device Port Config URL: ' + str(url))

    [port_config_post_response, port_config_post_json] = request_post(url, (self.username_in, self.password_in), port_config_com)

    log.info('\tPrinting POST Device Port Config Result')
    log.info(pformat(port_config_post_json))
    log.info('\tStatus Code: ' + str(port_config_post_json['status']))

    time.sleep(0.5)
    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, port_config_post_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, port_config_post_json['status'], '200')
        verify_pass_or_fail_port_config(self, port_config_post_json, device_id, port_id, ip_address, port_name, port_config_com,
                                        speed, access_vlan, shutdown_res, duplex)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_device_by_id(self, param_in_dict):
    log.info('\tPerforming GET Device By ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevice IP Address missing')

    ip_address = param_in_dict['ip_address']
    log.info('\tIP Address for GET Device by ID: ' + str(ip_address))

    if str(self.expected_in[0]) == '400':
        device_id = str(ip_address)
    else:
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            device_id = int(device_id)

    log.info('\tDevice ID for GET Device by ID: ' + str(device_id))

    url = self.url_path + '/' + str(device_id)
    [device_id_get_response, device_id_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Device By ID Result')
    log.info(pformat(device_id_get_json))
    log.info('\tStatus Code: ' + str(device_id_get_json['status']))

    time.sleep(0.5)
    verify_pass_or_fail_status_code(self, self.h_method, device_id_get_json['status'], self.expected_in[0])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_devices(self, param_in_dict):
    log.info('\tPerforming DELETE Devices')

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevices IP Address missing')
    if 'delete_from_state' not in param_in_dict:
        self.failed('\tDevices delete_from_state missing')

    ip_address = param_in_dict['ip_address']
    if type(ip_address) is not list:
        ip_address = [ip_address]
    for ip in ip_address:
        log.info('\tIP Address for DELETE Devices: ' + str(ip))

    if 'privilege_test' in param_in_dict:
        if param_in_dict['privilege_test'] == 'True':
            discovery_profile_file = self.param_in['discovery_profile_file']
            access_profile_file = self.param_in['access_profile_file']
            test_path = str((os.path.dirname(os.path.abspath(__file__))))
            access_profile = read_json_data(test_path + '/' + str(access_profile_file))

            log.info('\tChanging Privilege mode on device')
            connect_to_device(ip_address, access_profile['deviceAccessSettings']['username'],
                              access_profile['deviceAccessSettings']['password'], 'privilege0')

            log.info('\tCalling Device Discovery')
            ip_scan_discovery(self.ind_info['ip'], self.username_in, self.password_in, discovery_profile_file,
                              access_profile_file, False)

    devices_id_list = []
    devices_id_dict = dict()

    if str(self.expected_in[0]) == '400':
        for i in range(0, len(ip_address)):
            devices_id_list.append(str(ip_address[i]))
    else:
        for i in range(0, len(ip_address)):
            device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address[i], 'id', False))
            if device_id != 'null':
                id_val = int(device_id)
                name_val = str(retrieve_device_info_by_ip(self.ind_info, ip_address[i], 'name', False))
                devices_id_list.append(id_val)
            else:
                id_val = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
                name_val = 'Null'
                devices_id_list.append(id_val)

            log.info('\tDevice ID for DELETE Devices: ' + str(id_val))
            devices_id_dict[str(ip_address[i])] = [str(id_val), str(self.expected_in[i]), str(name_val)]

            if 'verify_details' in param_in_dict:
                if param_in_dict['verify_details'] == 'True':
                    detail_fields = param_in_dict['details']
                    if type(detail_fields) is not list:
                        detail_fields = [detail_fields]

                    for detail in detail_fields:
                        rest_entry = str(retrieve_device_info_by_ip(self.ind_info, ip_address[i], detail.split(':')[0], False))
                        if detail.split(':')[1] != str(rest_entry):
                            log.info('\tExpected value for attribute: ' + str(detail.split(':')[0]) + ' is: ' + str(detail.split(':')[1]))
                            log.info('\tActual value for attribute: ' + str(detail.split(':')[0]) + ' is: ' + str(rest_entry))
                            self.failed('\tDevice Detail entry for attribute: ' + str(detail.split(':')[0]) + ' incorrect')

        if param_in_dict['delete_from_state'] != 'null':
            log.info('\tChanging state of Devices to: ' + str(param_in_dict['delete_from_state']) + ' state')
            change_state(self.ind_info, devices_id_list, param_in_dict['delete_from_state'])

    json_data_in = dict()
    json_data_in['ids'] = devices_id_list
    log.info('\tPrinting DELETE Devices parameters')
    log.info(pformat(json_data_in))

    [devices_delete_response, devices_delete_json] = request_delete(self.url_path, (self.username_in, self.password_in), json_data_in)

    log.info('\tPrinting DELETE Devices Result')
    log.info(pformat(devices_delete_json))
    log.info('\tStatus Code: ' + str(devices_delete_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, devices_delete_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, devices_delete_json['status'], '200')
        verify_pass_or_fail_state_change_or_delete(self, self.h_method, devices_delete_json, devices_id_dict, 'Deletion')

    if 'privilege_test' in param_in_dict:
        if param_in_dict['privilege_test'] == 'True':
            log.info('\tChanging Privilege mode on device')
            connect_to_device(ip_address, access_profile['deviceAccessSettings']['username'],
                              access_profile['deviceAccessSettings']['password'], 'privilege15')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def post_devices_state_change(self, param_in_dict):
    log.info('\tPerforming POST Devices State Change')

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevices IP Address missing')
    if 'old_state' not in param_in_dict:
        self.failed('\tDevices old state Address missing')
    if 'new_state' not in param_in_dict:
        self.failed('\tDevices new state Address missing')

    ip_address = param_in_dict['ip_address']
    if type(ip_address) is not list:
        ip_address = [ip_address]
    for ip in ip_address:
        log.info('\tIP Address for POST Devices State Change: ' + str(ip))

    devices_id_list = []
    devices_id_dict = dict()

    if str(self.expected_in[0]) == '400' and not all(is_valid_ip(ip) for ip in ip_address):
        for i in range(0, len(ip_address)):
            devices_id_list.append(str(ip_address[i]))
    else:
        for i in range(0, len(ip_address)):
            device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address[i], 'id', False))
            if device_id != 'null':
                id_val = int(device_id)
                name_val = str(retrieve_device_info_by_ip(self.ind_info, ip_address[i], 'name', False))
                devices_id_list.append(id_val)
            else:
                id_val = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
                name_val = 'Null'
                devices_id_list.append(id_val)

            log.info('\tDevice ID for POST Devices State Change: ' + str(id_val))
            devices_id_dict[str(ip_address[i])] = [str(id_val), str(self.expected_in[i]), str(name_val)]

        perform_device_transition(self, devices_id_list)

    json_data_in = dict()
    json_data_in['ids'] = devices_id_list
    json_data_in['newDeviceAdminStateStr'] = param_in_dict['new_state']
    log.info('\tPrinting POST Devices State Change parameters')
    log.info(pformat(json_data_in))

    url = self.url_path + '/admin-state-transition/tasks'
    log.info('\tURL: ' + str(url))

    if 'delete_nms' in param_in_dict:
        if param_in_dict['delete_nms'] == 'True':
            access_profile_file = self.param_in['access_profile_file']
            test_path = str((os.path.dirname(os.path.abspath(__file__))))
            access_profile = read_json_data(test_path + '/' + str(access_profile_file))

            log.info('\tDeleting flash:nms.odm on device')
            connect_to_device(ip_address, access_profile['deviceAccessSettings']['username'],
                              access_profile['deviceAccessSettings']['password'], 'nms_odm')

    [devices_post_response, devices_post_json] = request_post(url, (self.username_in, self.password_in), json_data_in)

    log.info('\tPrinting POST Devices State Change Response')
    log.info(pformat(devices_post_json))
    log.info('\tStatus Code: ' + str(devices_post_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, devices_post_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, devices_post_json['status'], '200')
        verify_pass_or_fail_state_change_or_delete(self, self.h_method, devices_post_json, devices_id_dict, 'State change')

    if 'backplane' in param_in_dict:
        if param_in_dict['backplane'] == 'True':
            url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/other-devices/' + str(devices_id_list[0]) + \
                  '/cip/extended-path-discovery/tasks'
            log.info('\tURL: ' + str(url))

            json_data_in = {"action": "extendedPathDiscovery"}
            log.info('\tPrinting POST Backplane bridging parameters')
            log.info(pformat(json_data_in))

            [backplane_post_response, backplane_post_json] = request_post(url, (self.username_in, self.password_in), json_data_in)
            verify_pass_or_fail_backplane(self, self.h_method, backplane_post_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_devices_admin_states(self, param_in_dict):
    log.info('\tPerforming GET Devices Admin States')

    if 'admin_states' not in param_in_dict:
        self.failed('\tDevices Admin States missing')

    admin_states_list = param_in_dict['admin_states']
    if type(admin_states_list) is not list:
        admin_states_list = [admin_states_list]

    url = self.url_path + '/device-admin-states'
    [device_states_get_response, device_states_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Device Admin States Result')
    log.info(pformat(device_states_get_json))
    log.info('\tStatus Code: ' + str(device_states_get_json['status']))

    verify_pass_or_fail_status_code(self, self.h_method, device_states_get_json['status'], self.expected_in[0])

    assert int(device_states_get_json['recordCount']) == 3, 'Devices does not have 3 admin states'
    assert sorted(list(device_states_get_json['records'])) == sorted(admin_states_list), \
        'Devices admin states incorrect values'


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_access_profiles(self, param_in_dict):
    log.info('\tPerforming DELETE Access Profiles')

    if 'access_profile_name' not in param_in_dict:
        self.failed('\tAccess Profile Name missing')

    access_profile_name = param_in_dict['access_profile_name']
    if type(access_profile_name) is not list:
        access_profile_name = [access_profile_name]

    for np_name in access_profile_name:
        log.info('\tAccess Profile Name for DELETE Access Profiles: ' + str(np_name))

    access_profile_id_list = []
    access_profile_id_dict = dict()
    for i in range(0, len(access_profile_name)):

        access_profile_id = retrieve_access_profile_info_by_name_or_id(self.ind_info, access_profile_name[i], 'id')
        if access_profile_id != 'null':
            id_val = str(access_profile_id)
            access_profile_id_list.append(id_val)
        else:
            id_val = str(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
            access_profile_id_list.append(id_val)

        log.info('\tAccess Profile ID for DELETE Access Profiles: ' + id_val)
        access_profile_id_dict[str(access_profile_name[i])] = [str(id_val), str(self.expected_in[i])]

    json_data_in = dict()
    json_data_in['ids'] = access_profile_id_list
    log.info('\tPrinting DELETE Access Profiles parameters')
    log.info(pformat(json_data_in))

    [delete_access_profiles_response, delete_access_profiles_json] = request_delete(self.url_path,
                                                                                    (self.username_in, self.password_in), json_data_in)

    log.info('\tPrinting DELETE Access Profiles Result')
    log.info(pformat(delete_access_profiles_json))
    log.info('\tStatus Code: ' + str(delete_access_profiles_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, delete_access_profiles_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, delete_access_profiles_json['status'], '200')
        verify_pass_or_fail_delete_access_profile(self, delete_access_profiles_json, access_profile_id_dict)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_other_devices_by_parameter(self, param_in_dict):
    log.info('\tPerforming GET All Other Devices by Parameter')
    limit_val = 2147483640
    offset_val = 0
    field_val = 'baseOtherDevice.name'
    direction_val = 'ASC'

    if 'limit' not in param_in_dict:
        self.failed('\tLimit value missing')
    if 'offset' not in param_in_dict:
        self.failed('\tOffset value missing')
    if 'field' not in param_in_dict:
        self.failed('\tField value missing')
    if 'direction' not in param_in_dict:
        self.failed('\tDirection value missing')

    if param_in_dict['limit'] != 'null':
        limit_val = param_in_dict['limit']
    if param_in_dict['offset'] != 'null':
        offset_val = param_in_dict['offset']
    if param_in_dict['field'] != 'null':
        field_val = param_in_dict['field']
    if param_in_dict['direction'] != 'null':
        direction_val = param_in_dict['direction']

    if 'search_string' not in param_in_dict and 'facets' not in param_in_dict:
        url = self.url_path + '?limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + \
              '&direction=' + str(direction_val)

    elif 'search_string' in param_in_dict:
        search_field = str(param_in_dict['search_string']).split('$')[0]
        search_value = str(param_in_dict['search_string']).split('$')[1]
        url = self.url_path + '?searchString=' + str(search_field) + ':"' + str(search_value) + \
              '"&limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + '&direction=' + str(direction_val)

    elif 'facets' in param_in_dict:
        facets_list = param_in_dict['facets']
        if type(param_in_dict['facets']) is not list:
            facets_list = [param_in_dict['facets']]

        facets_string = ''
        for facet in facets_list:
            facets_string += facet.split('$')[0] + ':' + facet.split('$')[1] + ','
        facets_string = facets_string[:-1]

        url = self.url_path + '?facets[]=' + str(facets_string) + \
              '&limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + '&direction=' + str(direction_val)

    log.info('\tGET All Other Devices by Parameter URL: ' + str(url))

    [other_get_response, other_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET All Other Devices by Parameter Result')
    log.info(pformat(other_get_json))
    log.info('\tStatus Code: ' + str(other_get_json['status']))

    if str(other_get_json['status']) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, other_get_json['status'], self.expected_in[0])

    elif 'search_string' in param_in_dict:
        verify_pass_or_fail_status_code(self, self.h_method, other_get_json['status'], '200')
        if other_get_json['recordCount'] == 0:
            self.failed('\tSearch failed; Check GET All Other Devices by Parameter result')
        for i in range(0, other_get_json['recordCount']):
            assert other_get_json['records'][i][str(search_field)] == str(search_value), \
                'Result of search is incorrect/Incorrect entry retrieved. Device is: ' + str(other_get_json['records'][i]['name'])
        log.info('\tSearch result correct')

    elif 'facets' in param_in_dict:
        verify_pass_or_fail_status_code(self, self.h_method, other_get_json['status'], '200')
        facet_lookup = device_facet_builder(other_get_json)
        if facet_lookup == {}:
            self.failed('\tFacet builder failed; Check GET All Other Devices by Parameter result')
        for facet in facets_list:
            assert int(facet_lookup[facet.split('$')[0]][facet.split('$')[1]]) >= 1, \
                'Facet filtering for baseOtherDevice.' + str(facet.split('$')[0]) + ' and value ' + str(facet.split('$')[1]) + ' incorrect'

    else:
        verify_pass_or_fail_status_code(self, self.h_method, other_get_json['status'], '200')
        verify_pass_or_fail_get_all(self, self.h_method, other_get_json['status'], self.expected_in[0], other_get_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_devices_by_parameter(self, param_in_dict):
    log.info('\tPerforming GET All Devices by Parameter')
    limit_val = 2147483640
    offset_val = 0
    field_val = 'device.name'
    direction_val = 'ASC'

    if 'limit' not in param_in_dict:
        self.failed('\tLimit value missing')
    if 'offset' not in param_in_dict:
        self.failed('\tOffset value missing')
    if 'field' not in param_in_dict:
        self.failed('\tField value missing')
    if 'direction' not in param_in_dict:
        self.failed('\tDirection value missing')

    if param_in_dict['limit'] != 'null':
        limit_val = param_in_dict['limit']
    if param_in_dict['offset'] != 'null':
        offset_val = param_in_dict['offset']
    if param_in_dict['field'] != 'null':
        field_val = param_in_dict['field']
    if param_in_dict['direction'] != 'null':
        direction_val = param_in_dict['direction']

    if 'search_string' not in param_in_dict and 'facets' not in param_in_dict:
        url = self.url_path + '?limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + \
              '&direction=' + str(direction_val)

    elif 'search_string' in param_in_dict:
        search_field = str(param_in_dict['search_string']).split('$')[0]
        search_value = str(param_in_dict['search_string']).split('$')[1]
        url = self.url_path + '?searchString=' + str(search_field) + ':"' + str(search_value) + \
              '"&limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + '&direction=' + str(direction_val)

    elif 'facets' in param_in_dict:
        facets_list = param_in_dict['facets']
        if type(param_in_dict['facets']) is not list:
            facets_list = [param_in_dict['facets']]

        facets_string = ''
        for facet in facets_list:
            facets_string += facet.split('$')[0] + ':' + facet.split('$')[1].replace(',', '%2C') + ','
        facets_string = facets_string[:-1]

        url = self.url_path + '?facets[]=' + str(facets_string) + \
              '&limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + '&direction=' + str(direction_val)

    log.info('\tGET All Devices by Parameter URL: ' + str(url))

    [devices_get_response, devices_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET All Devices by Parameter Result')
    log.info(pformat(devices_get_json))
    log.info('\tStatus Code: ' + str(devices_get_json['status']))

    if str(devices_get_json['status']) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, devices_get_json['status'], self.expected_in[0])

    elif 'search_string' in param_in_dict:
        verify_pass_or_fail_status_code(self, self.h_method, devices_get_json['status'], '200')
        if devices_get_json['recordCount'] == 0:
            self.failed('\tSearch failed; Check GET All Devices by Parameter result')
        for i in range(0, devices_get_json['recordCount']):
            assert str(devices_get_json['records'][i][str(search_field)]) == str(search_value), \
                'Result of search is incorrect/Incorrect entry retrieved. Device is: ' + str(devices_get_json['records'][i]['name']) + \
                '; Search value is: ' + repr(search_value) + ' , Result is: ' + repr(devices_get_json['records'][i][str(search_field)])
        log.info('\tSearch result correct')

    elif 'facets' in param_in_dict:
        verify_pass_or_fail_status_code(self, self.h_method, devices_get_json['status'], '200')
        facet_lookup = device_facet_builder(devices_get_json)
        if facet_lookup == {}:
            self.failed('\tFacet builder failed; Check GET All Devices by Parameter result')
        for facet in facets_list:
            assert int(facet_lookup[facet.split('$')[0]][facet.split('$')[1]]) >= 1, \
                'Facet filtering for baseOtherDevice.' + str(facet.split('$')[0]) + ' and value ' + str(facet.split('$')[1]) + ' incorrect'

    else:
        verify_pass_or_fail_status_code(self, self.h_method, devices_get_json['status'], '200')
        verify_pass_or_fail_get_all(self, self.h_method, devices_get_json['status'], self.expected_in[0], devices_get_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_other_device_types(self, param_in_dict):
    if 'device' not in param_in_dict:
        self.failed('\tOther Device type missing')
    if 'device_types' not in param_in_dict:
        self.failed('\tOther Device Device Types missing')

    log.info('\tPerforming GET ' + str(param_in_dict['device']) + ' Device Types')

    types_list = param_in_dict['device_types']
    if type(types_list) is not list:
        types_list = [types_list]

    log.info('\tGET ' + str(param_in_dict['device']) + ' Device Types list:\n' + str(pformat(types_list)))

    url = self.url_path + '/' + str(param_in_dict['device']).lower().replace(' ', '') + '-device-types-meta'

    log.info('\tGET ' + str(param_in_dict['device']) + ' Device Types URL: ' + str(url))
    [device_types_get_response, device_types_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET ' + str(param_in_dict['device']) + ' Device Types Result')
    log.info(pformat(device_types_get_json))
    log.info('\tStatus Code: ' + str(device_types_get_json['status']))

    verify_pass_or_fail_status_code(self, self.h_method, device_types_get_json['status'], self.expected_in[0])

    assert sorted(list(device_types_get_json['record'])) == sorted(types_list), \
        str(param_in_dict['device']) + ' Device types incorrect values'


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_other_device_by_id(self, param_in_dict):
    if 'device' not in param_in_dict:
        self.failed('\tOther Device type missing')

    log.info('\tPerforming GET ' + str(param_in_dict['device']) + ' Device By ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\t' + str(param_in_dict['device']) + ' Device IP Address missing')

    ip_address = param_in_dict['ip_address']
    log.info('\tIP Address for GET ' + str(param_in_dict['device']) + ' Device by ID: ' + str(ip_address))

    if str(self.expected_in[0]) == '400':
        other_device_id = str(ip_address)
    else:
        other_device_id = str(retrieve_other_device_info_by_ip(self.ind_info, ip_address, 'id', False))

        if other_device_id == 'null':
            other_device_id = str(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
    log.info('\t' + str(param_in_dict['device']) + ' Device ID for GET ' + str(param_in_dict['device']) +
             ' Device by ID: ' + other_device_id)

    url = self.url_path + '/' + str(other_device_id) + '/' + str(param_in_dict['device']).lower().replace(' ', '')
    log.info('\tURL: ' + str(url))

    [other_id_get_response, other_id_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET ' + str(param_in_dict['device']) + ' Device by ID Result')
    log.info(pformat(other_id_get_json))
    log.info('\tStatus Code: ' + str(other_id_get_json['status']))

    time.sleep(0.5)
    verify_pass_or_fail_status_code(self, self.h_method, other_id_get_json['status'], self.expected_in[0])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def put_other_device_by_id(self, param_in_dict):
    if 'device' not in param_in_dict:
        self.failed('\tOther Device type missing')

    log.info('\tPerforming PUT ' + str(param_in_dict['device']) + ' Device By ID')
    device_type = 'IO'

    if 'ip_address' not in param_in_dict:
        self.failed('\tOther Device IP Address missing')
    if 'device_type' not in param_in_dict:
        self.failed('\tOther Device deviceType missing')

    if param_in_dict['device_type'] != 'null':
        device_type = param_in_dict['device_type']

    if param_in_dict['device'] not in other_device_protocols:
        self.failed('Incorrect Device Protocol ' + str(param_in_dict['device']))

    ip_address = param_in_dict['ip_address']
    log.info('\tIP Address for PUT ' + str(param_in_dict['device']) + ' Device By ID: ' + str(ip_address))

    if str(self.expected_in[0]) == '400' and not is_valid_ip(ip_address):
        other_device_id = str(ip_address)
    else:
        other_device_id = str(retrieve_other_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if other_device_id == 'null':
            other_device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            protocol = str(retrieve_other_device_info_by_ip(self.ind_info, ip_address, 'protocolStr', False))
            if protocol != str(param_in_dict['device']):
                self.failed('Other Device ' + str(ip_address) + ' is not ' + str(param_in_dict['device']))

    log.info('\t' + str(param_in_dict['device']) + ' Device ID for PUT ' + str(param_in_dict['device']) + ' Device By ID: ' +
             str(other_device_id))

    url = self.url_path + '/' + str(other_device_id) + '/' + str(param_in_dict['device']).lower().replace(' ', '')
    log.info('\tPUT ' + str(param_in_dict['device']) + ' Device By ID URL: ' + str(url))

    json_data_in = dict()
    json_data_in['deviceType'] = str(device_type)
    log.info('\tPrinting PUT ' + str(param_in_dict['device']) + ' Device By ID parameters')
    log.info(pformat(json_data_in))

    [other_put_response, other_put_json] = request_put(url, (self.username_in, self.password_in), json_data_in)

    log.info('\tPrinting PUT ' + str(param_in_dict['device']) + ' Device By ID Result')
    log.info(pformat(other_put_json))
    log.info('\tStatus Code: ' + str(other_put_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, other_put_json['status'], self.expected_in[0])
    else:
        time.sleep(2)
        verify_pass_or_fail_status_code(self, self.h_method, other_put_json['status'], '200')
        modified_device_type = str(retrieve_other_device_info_by_ip(self.ind_info, ip_address, 'deviceType', False))
        log.info('\tModified deviceType is: ' + str(modified_device_type))
        if modified_device_type != str(device_type):
            self.failed('\t' + str(param_in_dict['device']) + ' Device Type unchanged')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_devices_export(self, param_in_dict):
    log.info('\tPerforming GET Devices Export')

    direction_val = 'ASC'

    if 'resourceAttributes' not in param_in_dict:
        self.failed('\tDevice Attributes value missing')
    if 'systemAttributes' not in param_in_dict:
        self.failed('\tSystem Attributes value missing')
    if 'fileType' not in param_in_dict:
        self.failed('\tFile Type value missing')

    resource_attributes = param_in_dict['resourceAttributes']
    if type(resource_attributes) is list:
        resource_attributes = ','.join([i for i in resource_attributes])
    system_attributes = param_in_dict['systemAttributes']
    if type(system_attributes) is list:
        system_attributes = ','.join([i for i in system_attributes])
    file_type = param_in_dict['fileType']
    if type(file_type) is list:
        file_type = ','.join([i for i in file_type])

    if 'limit' in param_in_dict:
        if 'offset' not in param_in_dict:
            self.failed('\tOffset value missing')
        if 'field' not in param_in_dict:
            self.failed('\tField value missing')
        if 'direction' not in param_in_dict:
            self.failed('\tDirection value missing')

        limit_val = 2147483640
        offset_val = 0
        field_val = 'device.name'
        direction_val = 'ASC'

        if param_in_dict['limit'] != 'null':
            limit_val = param_in_dict['limit']
        if param_in_dict['offset'] != 'null':
            offset_val = param_in_dict['offset']
        if param_in_dict['field'] != 'null':
            field_val = param_in_dict['field']
        if param_in_dict['direction'] != 'null':
            direction_val = param_in_dict['direction']

        url = self.url_path + '/export?resourceAttributes=' + str(resource_attributes) + '&systemAttributes=' + \
              str(system_attributes) + '&fileType=' + str(file_type) + \
              '&limit=' + str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + \
              '&direction=' + str(direction_val)

    elif 'search_string' in param_in_dict:
        search_field = str(param_in_dict['search_string']).split('$')[0]
        search_value = str(param_in_dict['search_string']).split('$')[1]
        url = self.url_path + '/export?searchString=' + str(search_field) + ':"' + str(search_value) + '"&resourceAttributes=' + \
              str(resource_attributes) + '&systemAttributes=' + str(system_attributes) + '&fileType=' + str(file_type) + \
              '&direction=' + str(direction_val)

    elif 'facets' in param_in_dict:
        facets_list = param_in_dict['facets']
        if type(param_in_dict['facets']) is not list:
            facets_list = [param_in_dict['facets']]

        facets_string = ''
        for facet in facets_list:
            facets_string += facet.split('$')[0] + ':' + facet.split('$')[1].replace(',', '%2C') + ','
        facets_string = facets_string[:-1]

        url = self.url_path + '/export?facets[]=' + str(facets_string) + '&resourceAttributes=' + \
              str(resource_attributes) + '&systemAttributes=' + str(system_attributes) + '&fileType=' + str(file_type) + \
              '&direction=' + str(direction_val)

    else:
        url = self.url_path + '/export?resourceAttributes=' + str(resource_attributes) + '&systemAttributes=' + \
              str(system_attributes) + '&fileType=' + str(file_type) + '&direction=' + str(direction_val)

    log.info('\tGET Devices Export URL: ' + str(url))

    export_get_response = request_get_file(url, (self.username_in, self.password_in))

    log.info('\tStatus Code: ' + str(export_get_response.status_code))

    file_name = get_filename_from_cd(export_get_response.headers.get('content-disposition'))

    if str(self.expected_in[0]) in ['400', '404']:
        try:
            export_get_json = export_get_response.json()
            assert str(export_get_json['status']) == str(self.expected_in[0]), 'GET Devices Export status incorrect'
        except Exception as msg:
            self.failed('\tGET Devices Export result not a JSON; ' + str(msg))
    else:
        if file_name is None:
            self.failed('\tGET Devices Export file not created')
        else:
            log.info('\tGET Devices Export file created: ' + str(file_name))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_alarms_summary_affected_devices_by_group(self, param_in_dict):
    log.info('\tPerforming GET Alarms Summary-Affected Devices By Group')

    if 'group_id' not in param_in_dict:
        self.failed('\tGroup ID missing')
    group_id = param_in_dict['group_id']

    if 'ip_address' not in param_in_dict:
        self.failed('\tDevice IP Address missing')

    if 'device_type' not in param_in_dict:
        self.failed('\tDevice Type missing')

    if 'alarms' not in param_in_dict:
        self.failed('\tAlarm missing')

    ip_address = param_in_dict['ip_address']
    if type(ip_address) is not list:
        ip_address = [ip_address]

    alarms = param_in_dict['alarms']
    if type(alarms) is not list:
        alarms = [alarms]

    device_type = param_in_dict['device_type']
    if type(device_type) is not list:
        device_type = [device_type]

    for dev_t in device_type:
        log.info('\tDevice Types for GET Alarms Summary-Affected Devices By Group: ' + str(dev_t))

    for i in range(0, len(ip_address)):
        log.info('\tGenerating alarm for Device: ' + str(ip_address[i]))
        generateEvents(self.ind_info['ip'], self.ind_info['username'],self.ind_info['password'], ip_address[i], alarms[i])

    url = self.url_path + '/affected-devices?groupId=' + str(group_id)
    for dev_t in device_type:
        url = url + '&deviceTypes[]=' + str(dev_t)

    log.info('\tURL: ' + str(url))

    [affected_devices_get_response, affected_devices_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Alarms Summary-Affected Devices By Group')
    log.info(pformat(affected_devices_get_json))
    log.info('\tStatus Code: ' + str(affected_devices_get_json['status']))

    time.sleep(0.5)
    verify_pass_or_fail_status_code(self, self.h_method, affected_devices_get_json['status'], self.expected_in[0])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_other_devices_connected_devices_by_id(self, param_in_dict):
    log.info('\tPerforming GET Other Devices Connected Devices by ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')

    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']

    if str(self.expected_in[0]) == '400':
        if 'limit' in param_in_dict:
            device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        else:
            device_id = str(ip_address)

    else:
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            device_id = int(device_id)

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'True':
                url_d = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices'
                [devices_get_response, devices_get_json] = request_get(url_d, (self.ind_info['username'], self.ind_info['password']))
                assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), \
                    'GET Devices response incorrect'

                id_list_unlicensed = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                                      if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Unlicensed']

                log.info('\tMoving all Devices to Licensed state')
                change_state(self.ind_info, id_list_unlicensed, 'Licensed')

        if 'topology' in param_in_dict:
            if param_in_dict['topology'] == 'True':
                perform_topology(self.ind_info)

    log.info('\tDevice ID for GET Other Devices Connected Devices by ID: ' + str(device_id))

    if 'limit' in param_in_dict:
        limit_val = 2147483640
        offset_val = 0
        field_val = 'connectedDevice.id'
        direction_val = 'ASC'

        if 'offset' not in param_in_dict:
            self.failed('\tOffset value missing')
        if 'direction' not in param_in_dict:
            self.failed('\tDirection value missing')
        if 'field' not in param_in_dict:
            self.failed('\tField value missing')

        if param_in_dict['limit'] != 'null':
            limit_val = param_in_dict['limit']
        if param_in_dict['offset'] != 'null':
            offset_val = param_in_dict['offset']
        if param_in_dict['field'] != 'null':
            field_val = param_in_dict['field']
        if param_in_dict['direction'] != 'null':
            direction_val = param_in_dict['direction']

        url = self.url_path + '/' + str(device_id) + '/connected-devices?limit=' + \
              str(limit_val) + '&offset=' + str(offset_val) + '&field=' + str(field_val) + '&direction=' + str(direction_val)

    else:
        url = self.url_path + '/' + str(device_id) + '/connected-devices'

    log.info('\tGET Other Devices Connected Devices by ID URL: ' + str(url))

    [other_connected_get_response, other_connected_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting Other Devices Connected Devices by ID Result')
    log.info(pformat(other_connected_get_json))
    log.info('\tStatus Code: ' + str(other_connected_get_json['status']))

    verify_pass_or_fail_status_code(self, self.h_method, other_connected_get_json['status'], self.expected_in[0])