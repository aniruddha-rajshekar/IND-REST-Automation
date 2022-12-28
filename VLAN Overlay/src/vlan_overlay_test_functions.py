from common_functions import *
from device_management_functions import *
from group_management_functions import create_single_group_under_root, associate_devices_to_group

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_vlans_by_group(self, param_in_dict):
    log.info('\tPerforming GET All Vlans by Group')

    if 'group_id' not in param_in_dict:
        self.failed('\tGroup ID missing')

    if param_in_dict['group_id'] != 'null':
        group_id = param_in_dict['group_id']

    if str(self.expected_in[0]) not in ['400', '404']:
        if 'licensed' not in param_in_dict:
            self.failed('\tLicensed or not missing')

        if param_in_dict['licensed'] == 'True':
            move_all_unlicensed_to_licensed(self)

        if param_in_dict['group_change'] == 'True':
            if 'group_name' not in param_in_dict:
                self.failed('\tGroup Name missing')
            if 'device_to_move' not in param_in_dict:
                self.failed('\tDevice to move missing')

            [grp_name, grp_id] = create_single_group_under_root(self.ind_info, param_in_dict['group_name'])
            device_id = retrieve_device_info_by_ip(self.ind_info, param_in_dict['device_to_move'], 'id', False)
            log.info('\tAssociating ' + str(param_in_dict['device_to_move']) + ' to group ' + str(grp_name))
            associate_devices_to_group(self.ind_info, grp_id, [device_id], True)
            time.sleep(3)

            url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices?groupId=1'
            [devices_get_response, devices_get_json] = request_get(url, (self.ind_info['username'], self.ind_info['password']))
            assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), 'GET Devices response incorrect'
            id_list_licensed = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                                if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Licensed']
            [grp_name_1, grp_id_1] = create_single_group_under_root(self.ind_info, 'Temp_Group')
            associate_devices_to_group(self.ind_info, grp_id_1, id_list_licensed, False)
            time.sleep(3)

            group_id = grp_id_1

    url = self.url_path + '?groupId=' + str(group_id)
    log.info('\tGET All Vlans by Group URL: ' + str(url))

    [vlans_get_response, vlans_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET All Vlans by Group Result')
    log.info(pformat(vlans_get_json))
    log.info('\tStatus Code: ' + str(vlans_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, vlans_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, vlans_get_json['status'], '200')
        verify_pass_or_fail_vlans(self, param_in_dict, vlans_get_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_topology_vlans_by_group(self, param_in_dict):
    log.info('\tPerforming GET Topology Vlans by Group')

    if 'group_id' not in param_in_dict:
        self.failed('\tGroup ID missing')
    if 'vlan_ids' not in param_in_dict:
        self.failed('\tVlan IDs missing')

    if param_in_dict['group_id'] != 'null':
        group_id = param_in_dict['group_id']
    if param_in_dict['vlan_ids'] != 'null':
        vlan_ids = param_in_dict['vlan_ids']
        if type(vlan_ids) is not list:
            vlan_ids = [vlan_ids]

    if 'licensed' in param_in_dict:
        if param_in_dict['licensed'] == 'True':
            move_all_unlicensed_to_licensed(self)

    url = self.url_path + '?groupId=' + str(group_id) + str(''.join(['&vlanIds%5B%5D=' + str(vlan_id) for vlan_id in vlan_ids]))

    if 'topology' in param_in_dict:
        if param_in_dict['topology'] == 'True':
            perform_topology(self.ind_info)
            with requests.session() as topo_session:
                url_topo = 'https://' + str(self.ind_info['ip']) + ':8443/api/v1/topo'
                topo_get_response = topo_session.get(url_topo, auth=(self.username_in, self.password_in),
                                                     verify=False, cert=None, headers=request_headers)
                assert (topo_get_response.status_code == 200 and topo_get_response.json()['status'] == 200), \
                    'GET Topology response incorrect'

                topo_vlans_get_response = topo_session.get(url, auth=(self.username_in, self.password_in),
                                                           verify=False, cert=None, headers=request_headers)
                topo_vlans_get_json = topo_vlans_get_response.json()
        else:
            [topo_vlans_get_response, topo_vlans_get_json] = request_get(url, (self.username_in, self.password_in))
    else:
        [topo_vlans_get_response, topo_vlans_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tGET Topology Vlans by Group URL: ' + str(url))
    log.info('\tPrinting GET Topology Vlans by Group Result')
    log.info(pformat(topo_vlans_get_json))
    log.info('\tStatus Code: ' + str(topo_vlans_get_json['status']))

    if str(self.expected_in[0]) in ['400', '404']:
        verify_pass_or_fail_status_code(self, self.h_method, topo_vlans_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, topo_vlans_get_json['status'], '200')
        verify_pass_or_fail_topology_vlans(self, param_in_dict, topo_vlans_get_json, vlan_ids)
