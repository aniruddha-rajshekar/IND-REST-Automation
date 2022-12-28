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
def get_ptp_topology_by_group(self, param_in_dict):
    log.info('\tPerforming GET PTP Topology by Group')
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

    else:
        try:
            group_id = int(group_id_or_name)
        except Exception as msg:
            pass

    if ip_address == 'None':
        device_id = 0
    elif is_valid_ip(ip_address):
        log.info('\tGM IP Address for GET PTP Topology by Group: ' + str(ip_address))
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            self.failed('\tGM Device with IP Address: ' + str(ip_address) + ' not in Inventory')

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'True':
                log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                change_state(self.ind_info, [int(device_id)], 'Licensed')

        if 'license_child_nodes' in param_in_dict:
            ring_devices_list = param_in_dict['license_child_nodes'].split(':')
            for ip in ring_devices_list:
                ring_id = str(retrieve_device_info_by_ip(self.ind_info, ip, 'id', False))
                if ring_id == 'null':
                    self.failed('\tDevice with IP Address: ' + str(ip) + ' not in Inventory')
                log.info('\tMoving Device: ' + str(ip) + ' to Licensed state')
                change_state(self.ind_info, [int(ring_id)], 'Licensed')

    else:
        device_id = ip_address

    if 'slot_value' in param_in_dict:
        url = self.url_path + '/' + str(device_id) + '?groupId=' + str(group_id_or_name) + '&slot=' + str(param_in_dict['slot_value'])
    else:
        url = self.url_path + '/' + str(device_id) + '?groupId=' + str(group_id_or_name)

    if 'topology' in param_in_dict:
        if param_in_dict['topology'] == 'True':
            perform_topology(self.ind_info)
        with requests.session() as topo_session:
            url_topo = 'https://' + str(self.ind_info['ip']) + ':8443/api/v1/topo?id=' + str(group_id_or_name)
            topo_get_response = topo_session.get(url_topo, auth=(self.username_in, self.password_in),
                                                 verify=False, cert=None, headers=request_headers)
            assert (topo_get_response.status_code == 200 and topo_get_response.json()['status'] == 200), \
                'GET Topology response incorrect'

            ptp_topology_get_response = topo_session.get(url, auth=(self.username_in, self.password_in),
                                                         verify=False, cert=None, headers=request_headers)
            ptp_topology_get_json = ptp_topology_get_response.json()
    else:
        [ptp_topology_get_response, ptp_topology_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tGET PTP Topology by Group URL: ' + str(url))
    log.info('\tPrinting GET PTP Topology by Group Result')
    log.info(pformat(ptp_topology_get_json))
    log.info('\tStatus Code: ' + str(ptp_topology_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_topology_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_topology_get_json['status'], '200')
        verify_pass_or_fail_ptp_topology(self, param_in_dict, ptp_topology_get_json['records'])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_ptp_node_summary_by_id(self, param_in_dict):
    log.info('\tPerforming GET PTP Node Summary by ID')

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

            if 'gm_ip' in param_in_dict:
                gm_ip = param_in_dict['gm_ip']
                if gm_ip == ip_address:
                    gm_id = str(retrieve_device_info_by_ip(self.ind_info, gm_ip, 'id', False))
                    if gm_id == 'null':
                        self.failed('\tPTP GM Device with IP Address: ' + str(gm_ip) + ' not in Inventory')
                else:
                    gm_id = str(retrieve_device_info_by_ip(self.ind_info, gm_ip, 'id', False))
                    if gm_id == 'null':
                        self.failed('\tPTP GM Device with IP Address: ' + str(gm_ip) + ' not in Inventory')
                    gm_state = str(retrieve_device_info_by_ip(self.ind_info, gm_ip, 'deviceAdminStateStr', False))
                    if str(gm_state) == 'Unlicensed':
                        log.info('\tMoving Device: ' + str(gm_ip) + ' to Licensed state')
                        change_state(self.ind_info, [int(gm_id)], 'Licensed')

            if 'parent_ip' in param_in_dict:
                parent_ip = param_in_dict['parent_ip']
                if parent_ip == ip_address:
                    parent_id = str(retrieve_device_info_by_ip(self.ind_info, parent_ip, 'id', False))
                    if parent_id == 'null':
                        self.failed('\tPTP Parent Device with IP Address: ' + str(parent_ip) + ' not in Inventory')
                else:
                    parent_id = str(retrieve_device_info_by_ip(self.ind_info, parent_ip, 'id', False))
                    if parent_id == 'null':
                        self.failed('\tPTP Parent Device with IP Address: ' + str(parent_ip) + ' not in Inventory')
                    parent_state = str(retrieve_device_info_by_ip(self.ind_info, parent_ip, 'deviceAdminStateStr', False))
                    if str(parent_state) == 'Unlicensed':
                        log.info('\tMoving Device: ' + str(parent_ip) + ' to Licensed state')
                        change_state(self.ind_info, [int(parent_id)], 'Licensed')

            if 'licensed' in param_in_dict:
                if param_in_dict['licensed'] == 'True':
                    log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                    change_state(self.ind_info, [int(device_id)], 'Licensed')

    log.info('\tDevice ID for GET PTP Node Summary by ID: ' + str(device_id))

    if 'gm_ip' in param_in_dict:
        if 'slot' in param_in_dict:
            url = self.url_path + '/' + str(device_id) + '/ptp-node-summary?gmNodeId=' + str(gm_id) + '&slot=' + str(param_in_dict['slot'])
        else:
            url = self.url_path + '/' + str(device_id) + '/ptp-node-summary?gmNodeId=' + str(gm_id)
    else:
        url = self.url_path + '/' + str(device_id) + '/ptp-node-summary'

    log.info('\tGET PTP Node Summary by ID URL: ' + str(url))
    [ptp_summary_get_response, ptp_summary_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET PTP Node Summary by ID Result')
    if str(self.expected_in[0]) in ['400', '404']:
        log.info(pformat(ptp_summary_get_json))
    else:
        if 'is_ptp' in param_in_dict:
            if param_in_dict['is_ptp'] == 'True':
                log.info(pformat(ptp_summary_get_json['record']['ptp']))
            elif param_in_dict['is_ptp'] == 'False':
                log.info(pformat(ptp_summary_get_json['record']))

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'False':
                log.info(pformat(ptp_summary_get_json['record']))

    log.info('\tStatus Code: ' + str(ptp_summary_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_summary_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_summary_get_json['status'], '200')
        if 'is_ptp' in param_in_dict:
            if param_in_dict['is_ptp'] == 'True':
                verify_pass_or_fail_ptp_node_summary(self, param_in_dict, ptp_summary_get_json['record']['ptp'])
            elif param_in_dict['is_ptp'] == 'False':
                verify_pass_or_fail_ptp_node_summary(self, param_in_dict, ptp_summary_get_json['record'])

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'False':
                if ptp_summary_get_json['record']['message'] != 'Please move the device to licensed state to monitor the PTP status.':
                    self.failed('\tGET PTP Node Summary by ID Result message for Unlicensed device incorrect')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_ptp_domain_summary_by_id(self, param_in_dict):
    log.info('\tPerforming GET PTP Domain Summary by ID')
    device_id = 0

    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')

    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']

    if 'clear_all' in param_in_dict:
        if param_in_dict['clear_all'] == 'True':
            clear_all(self.ind_info['ip'], self.username_in, self.password_in)

    if str(self.expected_in[0]) == '404':
        device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))

    elif is_valid_ip(ip_address):
        log.info('\tIP Address for GET PTP Domain Summary by ID: ' + str(ip_address))
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(ip_address) + ' not in Inventory')

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'True':
                log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                change_state(self.ind_info, [int(device_id)], 'Licensed')

        if 'license_child_nodes' in param_in_dict:
            ring_devices_list = param_in_dict['license_child_nodes'].split(':')
            for ip in ring_devices_list:
                ring_id = str(retrieve_device_info_by_ip(self.ind_info, ip, 'id', False))
                if ring_id == 'null':
                    self.failed('\tDevice with IP Address: ' + str(ip) + ' not in Inventory')
                log.info('\tMoving Device: ' + str(ip) + ' to Licensed state')
                change_state(self.ind_info, [int(ring_id)], 'Licensed')

    else:
        device_id = ip_address

    url = self.url_path + '/' + str(device_id) + '/ptpDomainSummary'

    log.info('\tGET PTP Domain Summary by ID URL: ' + str(url))
    [ptp_domain_get_response, ptp_domain_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET PTP Domain Summary by ID Result')
    log.info(pformat(ptp_domain_get_json))
    log.info('\tStatus Code: ' + str(ptp_domain_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_domain_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_domain_get_json['status'], '200')
        verify_pass_or_fail_ptp_domain_summary(self, param_in_dict, ptp_domain_get_json['records'][0])


###########################################################################################################################################
###########################################################################################################################################
def put_ptp_gm_offset_threshold_by_id(self, param_in_dict):
    log.info('\tPerforming PUT PTP GM Offset Threshold by ID')

    if 'ip_address' not in param_in_dict:
        self.failed('\tIP Address missing')

    if 'gm_offset_threshold' not in param_in_dict:
        self.failed('\tGM Offset Threshold missing')

    if param_in_dict['ip_address'] != 'null':
        ip_address = param_in_dict['ip_address']

    if param_in_dict['gm_offset_threshold'] != 'null':
        gm_offset_threshold = param_in_dict['gm_offset_threshold']

    if 'clear_all' in param_in_dict:
        if param_in_dict['clear_all'] == 'True':
            clear_all(self.ind_info['ip'], self.username_in, self.password_in)

    if str(self.expected_in[0]) == '404' and param_in_dict['is_ptp'] == 'False':
        device_id = int(random.randint(int(sys.maxsize * 0.75), int(sys.maxsize - 20)))
        ptp_id = device_id

    elif is_valid_ip(ip_address):
        log.info('\tIP Address for PTP GM Offset Threshold by ID: ' + str(ip_address))
        device_id = str(retrieve_device_info_by_ip(self.ind_info, ip_address, 'id', False))
        if device_id == 'null':
            self.failed('\tDevice with IP Address: ' + str(ip_address) + ' not in Inventory')

        if 'licensed' in param_in_dict:
            if param_in_dict['licensed'] == 'True':
                log.info('\tMoving Device: ' + str(ip_address) + ' to Licensed state')
                change_state(self.ind_info, [int(device_id)], 'Licensed')

        ptp_id = get_ptp_id_for_offset_test(self, int(device_id))

    else:
        device_id = ip_address
        ptp_id = device_id

    url = self.url_path + '/' + str(device_id) + '/ptpDevice/' + str(ptp_id) + '/gmOffsetThreshold/' + str(gm_offset_threshold)

    log.info('\tPUT PTP GM Offset Threshold by ID URL: ' + str(url))
    [ptp_offset_put_response, ptp_offset_put_json] = request_put(url, (self.username_in, self.password_in), {})

    log.info('\tPrinting PUT PTP GM Offset Threshold by ID Result')
    log.info(pformat(ptp_offset_put_json))
    log.info('\tStatus Code: ' + str(ptp_offset_put_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_offset_put_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, ptp_offset_put_json['status'], '200')
        verify_pass_or_fail_ptp_gm_offset_threshold(self, param_in_dict, ptp_offset_put_json['record'], int(device_id))