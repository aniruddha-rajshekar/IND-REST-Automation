from common_functions import *
from group_management_functions import delete_all_groups

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def ip_scan_discovery(ind_ip, ind_username, ind_password, discovery_profile_file_name, access_profile_file_name, clear_ind):
    assert (type(ind_ip) == str and is_valid_ip(ind_ip)), 'Invalid IP address'
    assert type(ind_username) == str, 'Username not a string'
    assert type(ind_password) == str, 'Password is not a string'
    assert type(clear_ind) == bool, 'Clear IND option must be True or False'
    ind_info = {'ip': str(ind_ip), 'username': str(ind_username), 'password': str(ind_password)}

    if clear_ind:
        clear_all(ind_ip, ind_username, ind_password)
    test_path = str((os.path.dirname(os.path.abspath(__file__))))
    [access_profile_id, temp] = post_access_profile(ind_info, read_json_data(test_path + '/' + str(access_profile_file_name)))
    discovery_profile_id = post_discovery_profile(ind_info, read_json_data(test_path + '/' + str(discovery_profile_file_name)),
                                                  access_profile_id)

    if perform_discovery(ind_info, discovery_profile_id, read_json_data(test_path + '/' + str(discovery_profile_file_name))['name']):
        log.info('\tDiscovery Done')
    else:
        return


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def retrieve_device_info_by_ip(ind_info, ip_address, device_info_parameter, return_json):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert (type(ip_address) == str and is_valid_ip(ip_address)), 'Invalid IP address'
    assert type(device_info_parameter) == str, 'Device information not a string'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
    [device_get_response, device_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (device_get_response.status_code == 200 and device_get_json['status'] == 200), \
        'GET Devices response incorrect'

    if return_json:
        device_info = [device_get_json['records'][i]
                       for i in range(0, device_get_json['recordCount'])
                       if ip_address == device_get_json['records'][i]['ipAddress']]
    else:
        device_info = [device_get_json['records'][i][device_info_parameter]
                       for i in range(0, device_get_json['recordCount'])
                       if ip_address == device_get_json['records'][i]['ipAddress']]

    if len(device_info) == 0:
        log.info('\tFailed to find Device: ' + str(ip_address))
        return 'null'

    return device_info[0]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def retrieve_other_device_info_by_ip(ind_info, ip_address, device_info_parameter, return_json):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert (type(ip_address) == str and is_valid_ip(ip_address)), 'Invalid IP address'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
    [devices_get_response, devices_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), 'GET Devices response incorrect'

    id_dict_other_devices = {devices_get_json['records'][i]['id']:
                                 devices_get_json['records'][i]['protocol'].lower()
                             for i in range(0, devices_get_json['recordCount'])
                             if devices_get_json['records'][i]['ipAddress'] == ip_address}

    if len(id_dict_other_devices):
        id_value = list(id_dict_other_devices.keys())[0]
        url = 'https://' + ind_info['ip'] + ':8443/api/v1/other-devices/' + str(id_value) + '/' + str(id_dict_other_devices[id_value])
        [devices_get_response, devices_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
        assert (devices_get_response.status_code == 200 and
                (devices_get_json['status'] == 200 or devices_get_json['status'] == 404)), \
            'GET Other Device by ID response incorrect'

        if return_json:
            return devices_get_json['record']
        else:
            return devices_get_json['record'][device_info_parameter]

    else:
        log.info('\tFailed to find Other Device: ' + str(ip_address))
        return 'null'


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def retrieve_access_profile_info_by_name_or_id(ind_info, access_profile_name_or_id, profile_info_parameter):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert (type(access_profile_name_or_id) == str or type(access_profile_name_or_id) == int), 'Access Profile name/Id incorrect'
    assert type(profile_info_parameter) == str, 'Access Profile information not a string'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/access-profiles'
    [access_profile_get_response, access_profile_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (access_profile_get_response.status_code == 200 and access_profile_get_json['status'] == 200), \
        'GET Access Profiles response incorrect'

    if type(access_profile_name_or_id) == str:
        try:
            access_profile_name_or_id = int(access_profile_name_or_id)
            is_id = True
        except ValueError:
            is_id = False
    elif type(access_profile_name_or_id) == int:
        is_id = True

    if is_id:
        access_profile_info = [access_profile_get_json['records'][i][profile_info_parameter]
                               for i in range(0, access_profile_get_json['recordCount'])
                               if access_profile_name_or_id == access_profile_get_json['records'][i]['id']]
    else:
        access_profile_info = [access_profile_get_json['records'][i][profile_info_parameter]
                               for i in range(0, access_profile_get_json['recordCount'])
                               if access_profile_name_or_id == access_profile_get_json['records'][i]['name']]

    if len(access_profile_info) == 0:
        return 'null'

    return access_profile_info[0]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def retrieve_discovery_profile_info_by_name_or_id(ind_info, discovery_profile_name_or_id, profile_info_parameter):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert (type(discovery_profile_name_or_id) == str or type(discovery_profile_name_or_id) == int), 'Discovery Profile name/Id incorrect'
    assert type(profile_info_parameter) == str, 'Discovery Profile information not a string'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/discovery-profiles'
    [discovery_profile_get_response, discovery_profile_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (discovery_profile_get_response.status_code == 200 and discovery_profile_get_json['status'] == 200), \
        'GET Discovery Profiles response incorrect'

    if type(discovery_profile_name_or_id) == str:
        try:
            discovery_profile_name_or_id = int(discovery_profile_name_or_id)
            is_id = True
        except ValueError:
            is_id = False
    elif type(discovery_profile_name_or_id) == int:
        is_id = True

    if is_id:
        discovery_profile_info = [discovery_profile_get_json['records'][i][profile_info_parameter]
                                  for i in range(0, discovery_profile_get_json['recordCount'])
                                  if discovery_profile_name_or_id == discovery_profile_get_json['records'][i]['id']]
    else:
        discovery_profile_info = [discovery_profile_get_json['records'][i][profile_info_parameter]
                                  for i in range(0, discovery_profile_get_json['recordCount'])
                                  if discovery_profile_name_or_id == discovery_profile_get_json['records'][i]['name']]

    if len(discovery_profile_info) == 0:
        return 'null'

    return discovery_profile_info[0]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def clear_all(ind_ip, ind_username, ind_password):
    assert (type(ind_ip) == str and is_valid_ip(ind_ip)), 'Invalid IP address '
    assert type(ind_username) == str, 'Username not a string'
    assert type(ind_password) == str, 'Password is not a string'

    ind_info = {
        'ip': str(ind_ip),
        'username': str(ind_username),
        'password': str(ind_password)
    }

    number_of_devices = sys.maxsize - 20
    number_of_trials = 10

    while number_of_devices > 0:
        delete_all_devices(ind_info)

        url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
        [devices_get_response, devices_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
        assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), 'GET Devices response incorrect'

        number_of_devices = devices_get_json['recordCount']
        number_of_trials -= 1
        if number_of_trials == 0:
            break

    log.info('\tDeleted All Devices')
    delete_all_discovery_profiles(ind_info)
    log.info('\tDeleted Discovery Profiles')
    delete_all_access_profiles(ind_info)
    log.info('\tDeleted Access Profiles')
    delete_all_groups(ind_info)
    log.info('\tDeleted All Groups')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_all_access_profiles(ind_info, *specific_access_profiles):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify correct credentials/ check ind_info_keys_list'
    list_access_profile = list(specific_access_profiles)

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/access-profiles'
    [access_profile_get_response, access_profile_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (access_profile_get_response.status_code == 200 and access_profile_get_json['status'] == 200), \
        'GET Access Profiles response incorrect'

    if access_profile_get_json['recordCount'] > 0:
        if not list_access_profile:
            id_list = [access_profile_get_json['records'][i]['id'] for i in range(0, access_profile_get_json['recordCount'])]
        else:
            id_list = [access_profile_get_json['records'][i]['id'] for i in range(0, access_profile_get_json['recordCount'])
                       if access_profile_get_json['records'][i]['name'] in list_access_profile]
        if not id_list:
            id_list = [2147483640]

        url = 'https://' + ind_info['ip'] + ':8443/api/v1/access-profiles'
        [access_profile_delete_response, access_profile_delete_json] = request_delete(url, (ind_info['username'], ind_info['password']),
                                                                                      {'ids': id_list})
        assert (access_profile_delete_response.status_code == 200 and access_profile_delete_json['status'] == 200), \
            'DELETE Access Profiles response incorrect'
    else:
        return


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_all_discovery_profiles(ind_info, *specific_discovery_profiles):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    list_discovery_profile = list(specific_discovery_profiles)

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/discovery-profiles'
    [discovery_profile_response, discovery_profile_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (discovery_profile_response.status_code == 200 and discovery_profile_json['status'] == 200), \
        'GET Discovery Profiles response incorrect'

    if discovery_profile_json['recordCount'] > 0:
        if not list_discovery_profile:
            id_list = [discovery_profile_json['records'][i]['id'] for i in range(0, discovery_profile_json['recordCount'])]
        else:
            id_list = [discovery_profile_json['records'][i]['id'] for i in range(0, discovery_profile_json['recordCount'])
                       if discovery_profile_json['records'][i]['name'] in list_discovery_profile]
        if not id_list:
            id_list = [2147483640]

        url = 'https://' + ind_info['ip'] + ':8443/api/v1/discovery-profiles'
        [discovery_profile_delete_response, discovery_profile_delete_json] = request_delete(url, (ind_info['username'],
                                                                                                  ind_info['password']),
                                                                                            {'ids': id_list})
        assert (discovery_profile_delete_response.status_code == 200 and discovery_profile_delete_json['status'] == 200), \
            'DELETE Discovery Profiles response incorrect'
    else:
        return


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_all_devices(ind_info):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
    [devices_get_response, devices_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), \
        'GET Devices response incorrect'

    devices_count = devices_get_json['recordCount']
    if devices_count != 0:
        pass
    else:
        devices_count = 0

    if devices_count > 0:
        id_list_unlicensed = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                               if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Unlicensed']
        if len(id_list_unlicensed) > 0:
            delete_unsupported_or_notapplicable_by_id(ind_info, id_list_unlicensed)

        id_list_notapplicable = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                                 if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Not Applicable']
        if len(id_list_notapplicable) > 0:
            delete_unsupported_or_notapplicable_by_id(ind_info, id_list_notapplicable)

        id_list_licensed = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                             if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Licensed']
        if len(id_list_licensed) > 0:
            change_state(ind_info, id_list_licensed, 'Unlicensed')

        delete_unsupported_or_notapplicable_by_id(ind_info, [devices_get_json['records'][i]['id']
                                                             for i in range(0, devices_get_json['recordCount'])])
    else:
        pass


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_all_other_devices(ind_info):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
    [devices_get_response, devices_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), 'GET Devices response incorrect'

    id_list_other_devices = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                             if devices_get_json['records'][i]['deviceCategory'] == 'OTHER']

    if len(id_list_other_devices):
        url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
        [devices_delete_response, devices_delete_json] = request_delete(url, (ind_info['username'], ind_info['password']),
                                                                    {'ids': id_list_other_devices})
        assert (devices_delete_response.status_code == 200 and
                (devices_delete_json['status'] == 200 or devices_delete_json['status'] == 404)), 'DELETE Devices response incorrect'

        wait_for_task_completion(ind_info, json.dumps(devices_delete_json['record']['taskId']))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_other_devices_by_id(ind_info, id_list):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(id_list) == list, 'Invalid ID list'
    assert all(isinstance(item, int) for item in id_list), 'All items in ID List not ints'

    if len(id_list):
        url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
        [devices_delete_response, devices_delete_json] = request_delete(url, (ind_info['username'], ind_info['password']),
                                                                    {'ids': id_list})
        assert (devices_delete_response.status_code == 200 and
                (devices_delete_json['status'] == 200 or devices_delete_json['status'] == 404)), 'DELETE Devices response incorrect'

        wait_for_task_completion(ind_info, json.dumps(devices_delete_json['record']['taskId']))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_unsupported_or_notapplicable_by_id(ind_info, id_list):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(id_list) == list, 'Invalid ID list'
    assert all(isinstance(item, int) for item in id_list), 'All items in ID List not ints'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
    [device_delete_response, device_delete_json] = request_delete(url, (ind_info['username'], ind_info['password']),
                                                                  {'ids': id_list})
    assert (device_delete_response.status_code == 200 and device_delete_json['status'] == 200), \
        'DELETE Devices response incorrect'

    wait_for_task_completion(ind_info, json.dumps(device_delete_json['record']['taskId']))


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def change_state(ind_info, devices_id_list, to_state):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(devices_id_list) == list, 'Invalid ID list'
    assert all(isinstance(item, int) for item in devices_id_list), 'All items in ID List not ints'
    assert (type(to_state) == str and str(to_state) in devices_states_list), 'Invalid Supported Device state'

    try:
        url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices/admin-state-transition/tasks'
        [devices_put_response, devices_put_json] = request_post(url, (ind_info['username'], ind_info['password']),
                                                                {'ids': devices_id_list, 'newDeviceAdminStateStr': str(to_state)})
        assert (devices_put_response.status_code == 200 and devices_put_json['status'] == 200), \
            'POST Devices State Change response incorrect'

        log.info('\tState change Task ID: ' + str(devices_put_json['record']['taskId']))
        wait_for_task_completion(ind_info, str(devices_put_json['record']['taskId']))
        log.info('\tState change complete')

        try:
            url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'
            [device_get_response, device_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
            assert (device_get_response.status_code == 200 and device_get_json['status'] == 200), 'GET Devices response incorrect'

            device_info = {device_get_json['records'][i]['ipAddress']: device_get_json['records'][i]['deviceAdminStateStr']
                           for i in range(0, device_get_json['recordCount'])
                           if device_get_json['records'][i]['id'] in devices_id_list}
            log.info(pformat(device_info))
        except Exception as msg:
            pass

        return True

    except Exception as msg:
        return False


###########################################################################################################################################
###########################################################################################################################################
def post_access_profile(ind_info, access_profile_json):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(access_profile_json) == dict, 'Invalid Access Profile'

    np_exists = False
    try:
        access_profile_id = retrieve_access_profile_info_by_name_or_id(ind_info, access_profile_json['name'], 'id')
        if access_profile_id != 'null':
            np_exists = True
        else:
            np_exists = False

        if not np_exists:
            url = 'https://' + ind_info['ip'] + ':8443/api/v1/access-profiles'
            [access_profile_post_response, access_profile_post_json] = request_post(url, (ind_info['username'], ind_info['password']),
                                                                                    access_profile_json)
            assert (access_profile_post_response.status_code == 200 and access_profile_post_json['status'] == 200), \
                'POST Access Profile response incorrect'

            return [retrieve_access_profile_info_by_name_or_id(ind_info, access_profile_json['name'], 'id'),
                    access_profile_post_json]
        else:
            return [access_profile_id, None]

    except Exception as msg:
        return ['null', None]


###########################################################################################################################################
###########################################################################################################################################
def post_discovery_profile(ind_info, discovery_profile_json, access_profile_id):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(discovery_profile_json) == dict, 'Invalid Discovery Profile'
    try:
        assert type(int(access_profile_id)) == int
    except ValueError:
        return 2147483640

    dp_exists = False
    access_profile_info = retrieve_access_profile_info_by_name_or_id(ind_info, access_profile_id, 'id')
    if access_profile_info == 'null':
        log.info('\tInvalid Access Profile ID: ' + str(access_profile_id) + '. Cannot create discovery profile')
        return 2147483640

    try:
        discovery_profile_id = retrieve_discovery_profile_info_by_name_or_id(ind_info, discovery_profile_json['name'], 'id')
        if discovery_profile_id != 'null':
            dp_exists = True
        else:
            dp_exists = False

        if not dp_exists:
            discovery_profile_json['accessProfileId'] = access_profile_id
            url = 'https://' + ind_info['ip'] + ':8443/api/v1/discovery-profiles'
            [discovery_profile_post_response, discovery_profile_post_json] = \
                request_post(url, (ind_info['username'], ind_info['password']), discovery_profile_json)
            assert (discovery_profile_post_response.status_code == 200 and discovery_profile_post_json['status'] == 200), \
                'POST Discovery Profile response incorrect'
            return discovery_profile_post_json['record']['id']
        else:
            return discovery_profile_id

    except Exception as msg:
        return 2147483640


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def perform_discovery(ind_info, discovery_profile_id, discovery_profile_name):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    try:
        assert type(int(discovery_profile_id)) == int
    except ValueError:
        log.info('\tInvalid Discovery Profile ID: ' + str(discovery_profile_id))
        return False

    if retrieve_discovery_profile_info_by_name_or_id(ind_info, discovery_profile_id, 'id') == 'null':
        log.info('\tDiscovery Profile does not exist. Cannot perform discovery')
        return False

    log.info('\tDiscovering Devices for profile ' + str(discovery_profile_name) + '...')
    url = 'https://' + ind_info['ip'] + ':8443/api/v1/discovery-profiles/' + str(discovery_profile_id) + '/tasks'
    [discovery_post_response, discovery_post_json] = request_post(url, (ind_info['username'], ind_info['password']),
                                                                  {"action": "discovery"})
    if discovery_post_json['status'] == 404:
        log.info('\tDiscovery Profile does not exist. Discovery was not performed')
        return False
    assert (discovery_post_response.status_code == 200 and discovery_post_json['status'] == 200), \
        'POST Discovery Profile Task response incorrect'

    log.info('\tDiscovery Task ID: ' + str(discovery_post_json['record']['lastSubmittedTaskId']))
    wait_for_task_completion(ind_info, json.dumps(discovery_post_json['record']['lastSubmittedTaskId']))

    return True


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def perform_topology(ind_info):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'

    log.info('\tPerforming On-Demand Topology...')
    url = 'https://' + ind_info['ip'] + ':8443/api/v1/topology/discoveries/tasks?groupId=1'
    [topology_post_response, topology_post_json] = request_post(url, (ind_info['username'], ind_info['password']),
                                                                {"action": "topologyDiscovery"})
    log.info(pformat(topology_post_json))
    assert (topology_post_response.status_code == 200 and topology_post_json['status'] == 200), \
        'POST Topology response incorrect'

    log.info('\tTopology Task ID: ' + str(topology_post_json['record']['id']))
    wait_for_task_completion(ind_info, topology_post_json['record']['id'])
    log.info('\tTopology complete')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def perform_device_transition(self, devices_id_list):
    assert type(devices_id_list) == list, 'Devices ID List not a list'
    log.info('\tPerforming Device Transition...')

    device_from_state = self.param_in['old_state']
    if type(device_from_state) is not list:
        device_from_state = [device_from_state]

    for i in range(0, len(devices_id_list)):
        change_state(self.ind_info, [devices_id_list[i]], device_from_state[i])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def move_all_unlicensed_to_licensed(self):
    url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices'
    [devices_get_response, devices_get_json] = request_get(url, (self.ind_info['username'], self.ind_info['password']))
    assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), 'GET Devices response incorrect'

    id_list_unlicensed = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                           if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Unlicensed']

    change_state(self.ind_info, id_list_unlicensed, 'Licensed')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def other_device_facet_builder(facet_json):
    assert type(facet_json) == dict, 'Facets JSON is not a dict'
    facet_lookup = {str(facet_item['name']).split('.')[1]: {} for facet_item in facet_json['facets']}
    for facet_item in facet_json['facets']:
        for facet_vos in facet_item['facetValueVos']:
            facet_lookup[str(facet_item['name']).split('.')[1]][str(facet_vos['value'])] = str(facet_vos['count'])
    return facet_lookup