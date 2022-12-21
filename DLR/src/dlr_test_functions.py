from common_functions import *
from device_management_functions import *
from group_management_functions import create_single_group_under_root
from group_management_functions import associate_devices_to_group

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_dlr_instances_by_group(self, param_in_dict):
    log.info('\tPerforming GET DLR Instances by Group')
    device_id = 0

    if 'group_id_or_name' not in param_in_dict:
        self.failed('\tGroup ID/ Name missing')
    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')

    if param_in_dict['group_id_or_name'] != 'null':
        group_id_or_name = param_in_dict['group_id_or_name']
    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']

    if 'clear_all' in param_in_dict:
        if param_in_dict['clear_all'] == 'True':
            clear_all(self.ind_info['ip'], self.username_in, self.password_in)

    if 'group_test' in param_in_dict:
        grp_name = str(group_id_or_name)
        [group_name, group_id] = create_single_group_under_root(self.ind_info, grp_name)
        group_id = int(group_id)

        url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices'
        [devices_get_response, devices_get_json] = request_get(url, (self.ind_info['username'], self.ind_info['password']))
        assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), \
            'GET Devices response incorrect'
        id_list_all = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])]

        associate_devices_to_group(self.ind_info, group_id, id_list_all)

    else:
        try:
            group_id = int(group_id_or_name)
        except Exception as msg:
            group_id = group_id_or_name

    if ip_address == 'None':
        device_id = 'None'
    elif ip_address != 'None':
        log.info('\tIP Address for GET DLR Instances by Group: ' + str(ip_address))
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(ip_address) + ' not in Inventory')

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'True':
                log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                change_state(self.ind_info, [int(device_id)], 'Licensed')

    url = self.url_path + '?groupId=' + str(group_id)
    log.info('\tGET DLR Instances by Group URL: ' + str(url))
    [dlr_instances_get_response, dlr_instances_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET DLR Instances by Group Result')
    log.info(pformat(dlr_instances_get_json))
    log.info('\tStatus Code: ' + str(dlr_instances_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_instances_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_instances_get_json['status'], '200')
        if param_in_dict['empty'] == 'No Check':
            pass
        else:
            verify_pass_or_fail_dlr_instances(self, param_in_dict, dlr_instances_get_json['records'], ip_address, device_id)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_dlr_topology_by_group(self, param_in_dict):
    log.info('\tPerforming GET DLR Topology by Group')
    device_id = 0

    if 'group_id_or_name' not in param_in_dict:
        self.failed('\tGroup ID/ Name missing')
    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')
    if 'instance_id' not in param_in_dict:
        self.failed('\tInstance ID missing')

    if param_in_dict['group_id_or_name'] != 'null':
        group_id_or_name = param_in_dict['group_id_or_name']
    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']
    if param_in_dict['instance_id'] != 'null':
        instance_id = param_in_dict['instance_id']

    if 'clear_all' in param_in_dict:
        if param_in_dict['clear_all'] == 'True':
            clear_all(self.ind_info['ip'], self.username_in, self.password_in)

    if 'group_test' in param_in_dict:
        if 'subgroup' not in param_in_dict:
            self.failed('\tSubgroup missing')
        if 'move_to_subgroup' not in param_in_dict:
            self.failed('\tDevice to move to Subgroup missing')
        if 'move_all_to_group' not in param_in_dict:
            self.failed('\tSubgroup to move all devices to missing')

        [subgroup_name, subgroup_id] = create_single_group_under_root(self.ind_info, 'grp2')
        subgroup_id = int(subgroup_id)
        move_devices_list = param_in_dict['move_all_to_group'].split(':')
        move_id_list = []
        for dev in move_devices_list:
            move_device_id = str(retrieve_device_info_by_ip(self.ind_info, dev, 'id', False))
            if move_device_id == 'null':
                self.failed('\tDevice with IP Address: ' + str(dev) + ' not in Inventory')
            move_id_list.append(int(move_device_id))

        associate_devices_to_group(self.ind_info, subgroup_id, move_id_list)

        grp_name = str(param_in_dict['subgroup'])
        [subgroup_name, subgroup_id] = create_single_group_under_root(self.ind_info, grp_name)
        subgroup_id = int(subgroup_id)

        move_devices_list = param_in_dict['move_to_subgroup'].split(':')
        move_id_list = []
        for dev in move_devices_list:
            move_device_id = str(retrieve_device_info_by_ip(self.ind_info, dev, 'id', False))
            if move_device_id == 'null':
                self.failed('\tDevice with IP Address: ' + str(dev) + ' not in Inventory')
            move_id_list.append(int(move_device_id))

        associate_devices_to_group(self.ind_info, subgroup_id, move_id_list)

        group_id_or_name = subgroup_id

    else:
        try:
            group_id = int(group_id_or_name)
        except Exception as msg:
            pass

    if instance_id == 'None':
        instance_id = 0

    if ip_address == 'None':
        device_id = 0
    elif is_valid_ip(ip_address):
        log.info('\tSupervisor IP Address for GET DLR Topology by Group: ' + str(ip_address))
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            self.failed('\tSupervisor Device with IP Address: ' + str(ip_address) + ' not in Inventory')

        if 'license_ring_devices' in param_in_dict:
            ring_devices_list = param_in_dict['license_ring_devices'].split(':')
            ring_id_list = []
            for ip in ring_devices_list:
                ring_id = str(retrieve_device_info_by_ip(self.ind_info, ip, 'id', False))
                if ring_id == 'null':
                    self.failed('\tDevice with IP Address: ' + str(ip) + ' not in Inventory')
                ring_id_list.append(int(ring_id))
            log.info('\tMoving Devices: ' + str(ring_devices_list) + ' to Licensed state')
            change_state(self.ind_info, ring_id_list, 'Licensed')

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'True':
                log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                change_state(self.ind_info, [int(device_id)], 'Licensed')

    else:
        device_id = ip_address

    if 'slot_value' in param_in_dict:
        url = self.url_path + '/' + str(device_id) + '?groupId=' + str(group_id_or_name) + \
          '&instanceId=' + str(instance_id) + '&slot=' + str(param_in_dict['slot_value'])
    else:
        url = self.url_path + '/' + str(device_id) + '?groupId=' + str(group_id_or_name) + '&instanceId=' + str(instance_id)

    if 'topology' in param_in_dict:
        if param_in_dict['topology'] == 'True':
            perform_topology(self.ind_info)
        with requests.session() as topo_session:
            url_topo = 'https://' + str(self.ind_info['ip']) + ':8443/api/v1/topo?id=' + str(group_id_or_name)
            topo_get_response = topo_session.get(url_topo, auth=(self.username_in, self.password_in),
                                                 verify=False, cert=None, headers=request_headers)
            assert (topo_get_response.status_code == 200 and topo_get_response.json()['status'] == 200), \
                'GET Topology response incorrect'

            dlr_topology_get_response = topo_session.get(url, auth=(self.username_in, self.password_in),
                                                         verify=False, cert=None, headers=request_headers)
            dlr_topology_get_json = dlr_topology_get_response.json()
    else:
        [dlr_topology_get_response, dlr_topology_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tGET DLR Topology by Group URL: ' + str(url))
    log.info('\tPrinting GET DLR Topology by Group Result')
    log.info(pformat(dlr_topology_get_json))
    log.info('\tStatus Code: ' + str(dlr_topology_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_topology_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_topology_get_json['status'], '200')
        verify_pass_or_fail_dlr_topology(self, param_in_dict, dlr_topology_get_json['record'], ip_address, device_id)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_dlr_device_details_by_id(self, param_in_dict):
    log.info('\tPerforming GET DLR Device Details by ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')

    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']

    if 'clear_all' in param_in_dict:
        if param_in_dict['clear_all'] == 'True':
            clear_all(self.ind_info['ip'], self.username_in, self.password_in)

    if str(self.expected_in[0]) == '400':
        device_id = str(ip_address)
    else:
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            device_id = int(device_id)

            if 'supervisor_ip' in param_in_dict:
                sup_ip = param_in_dict['supervisor_ip']
                if sup_ip == ip_address:
                    pass
                else:
                    sup_state = str(retrieve_device_info_by_ip(self.ind_info, sup_ip, 'deviceAdminStateStr', False))
                    if sup_state == 'null':
                        self.failed('\tSupervisor Device with IP Address: ' + str(sup_ip) + ' not in Inventory')
                    if str(sup_state) == 'Unlicensed':
                        sup_id = str(retrieve_device_info_by_ip(self.ind_info, sup_ip, 'id', False))
                        log.info('\tMoving Device: ' + str(sup_ip) + ' to Licensed state')
                        change_state(self.ind_info, [int(sup_id)], 'Licensed')

            if 'licensed' in param_in_dict:
                if param_in_dict['licensed'] == 'True':
                    log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                    change_state(self.ind_info, [int(device_id)], 'Licensed')

    log.info('\tDevice ID for GET DLR Device Details by ID: ' + str(device_id))

    url = self.url_path + '/' + str(device_id) + '/dlr'
    log.info('\tGET DLR Device Details by ID URL: ' + str(url))
    [dlr_details_get_response, dlr_details_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET DLR Device Details by ID Result')
    log.info(pformat(dlr_details_get_json))
    log.info('\tStatus Code: ' + str(dlr_details_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_details_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_details_get_json['status'], '200')
        verify_pass_or_fail_dlr_device_details(self, param_in_dict, dlr_details_get_json['records'], ip_address, device_id)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_dlr_node_summary_by_id(self, param_in_dict):
    log.info('\tPerforming GET DLR Node Summary by ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')

    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']

    if 'clear_all' in param_in_dict:
        if param_in_dict['clear_all'] == 'True':
            clear_all(self.ind_info['ip'], self.username_in, self.password_in)

    if str(self.expected_in[0]) == '400':
        device_id = str(ip_address)
        if 'supervisor_ip' in param_in_dict:
            sup_id = param_in_dict['supervisor_ip']

    else:
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        else:
            device_id = int(device_id)

            if 'supervisor_ip' in param_in_dict:
                sup_ip = param_in_dict['supervisor_ip']
                if sup_ip == ip_address:
                    sup_id = device_id
                else:
                    sup_state = str(retrieve_device_info_by_ip(self.ind_info, sup_ip, 'deviceAdminStateStr', False))
                    if sup_state == 'null':
                        if str(self.expected_in[0]) == '404':
                            pass
                        else:
                            if 'no_sup' in param_in_dict:
                                sup_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
                            else:
                                self.failed('\tSupervisor Device with IP Address: ' + str(sup_ip) + ' not in Inventory')

                    if str(self.expected_in[0]) == '404':
                        sup_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
                    else:
                        if 'no_sup' in param_in_dict:
                            sup_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
                        else:
                            sup_id = str(retrieve_device_info_by_ip(self.ind_info, sup_ip, 'id', False))
                            if str(sup_state) == 'Unlicensed':
                                log.info('\tMoving Device: ' + str(sup_ip) + ' to Licensed state')
                                change_state(self.ind_info, [int(sup_id)], 'Licensed')

            if 'licensed' in param_in_dict:
                if param_in_dict['licensed'] == 'True':
                    log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                    change_state(self.ind_info, [int(device_id)], 'Licensed')

    log.info('\tDevice ID for GET DLR Node Summary by ID: ' + str(device_id))
    time.sleep(2)

    if 'supervisor_ip' in param_in_dict and 'instance_id' in param_in_dict:
        url = self.url_path + '/' + str(device_id) + '/dlr-node-summary?supervisorNodeId=' + str(sup_id) + '&instanceId=' + \
              str(param_in_dict['instance_id'])

    elif 'supervisor_ip' in param_in_dict and 'instance_id' not in param_in_dict:
        url = self.url_path + '/' + str(device_id) + '/dlr-node-summary?supervisorNodeId=' + str(sup_id)

    elif 'supervisor_ip' not in param_in_dict and 'instance_id' in param_in_dict:
        url = self.url_path + '/' + str(device_id) + '/dlr-node-summary?instanceId=' + str(param_in_dict['instance_id'])

    else:
        url = self.url_path + '/' + str(device_id) + '/dlr-node-summary'
        if 'slot' in param_in_dict:
            url = url + '?slot=' + str(param_in_dict['slot'])

    if 'slot' in param_in_dict:
        url = url + '&slot=' + str(param_in_dict['slot'])

    log.info('\tGET DLR Node Summary by ID URL: ' + str(url))
    [dlr_node_summary_get_response, dlr_node_summary_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET DLR Node Summary by ID Result')
    if str(self.expected_in[0]) in ['400', '404']:
        log.info(pformat(dlr_node_summary_get_json))
    else:
        log.info(pformat(dlr_node_summary_get_json['record']['dlr']))
    log.info('\tStatus Code: ' + str(dlr_node_summary_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_node_summary_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, dlr_node_summary_get_json['status'], '200')
        verify_pass_or_fail_dlr_node_summary(self, param_in_dict, dlr_node_summary_get_json['record'])