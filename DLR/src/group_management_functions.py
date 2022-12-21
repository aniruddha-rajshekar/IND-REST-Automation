from common_functions import *
from rest_functions import request_get, request_delete, request_post, request_put


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def create_single_group_under_root(ind_info, group_name):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(group_name) == str, 'Group Name is not a string'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/groups'
    root_group_dict = {'description': 'Subgroup under Root Group', 'name': str(group_name), 'parentId': 1}

    [groups_get_response, groups_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (groups_get_response.status_code == 200 and groups_get_json['status'] == 200), 'GET Groups response incorrect'
    children_groups = groups_get_json['record']['children']
    for child in children_groups:
        if child['name'] == str(group_name):
            return [child['name'], child['id']]

    log.info('\tCreating subgroup under Root Group')
    [groups_post_response, groups_post_json] = request_post(url, (ind_info['username'], ind_info['password']), root_group_dict)
    assert (groups_post_response.status_code == 200 and groups_post_json['status'] == 200), 'POST Groups response incorrect'

    return [root_group_dict['name'], groups_post_json['record']['id']]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def create_group_structure(ind_info, level_by_level):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert 'by' in str(level_by_level), 'Level by level must be in the form NbyN'

    log.info('\tCreating Group structure: ' + str(level_by_level))
    lbyl = str(level_by_level).split('by')
    parent_id = 1
    url = 'https://' + ind_info['ip'] + ':8443/api/v1/groups'
    group_json_data = {'description': 'Subgroup', 'name': 'G', 'parentId': 1}

    for i in range(int(lbyl[0])):
        group_dict = {}
        group_dict['description'] = group_json_data['description'] + str(i + 1)
        group_dict['name'] = group_json_data['name'] + str(i + 1)
        group_dict['parentId'] = parent_id
        for j in range(int(lbyl[1])):
            [groups_post_response, groups_post_json] = request_post(url, (ind_info['username'], ind_info['password']), group_dict)
            assert (groups_post_response.status_code == 200 and groups_post_json['status'] == 200), 'POST Group response incorrect'

            if groups_post_json['status'] == 200:
                group_dict = {}
                group_dict['description'] = group_json_data['description'] + str(i) + '_' + str(j + 1)
                group_dict['name'] = group_json_data['name'] + str(i + 1) + '_' + str(j + 1)
                group_dict['parentId'] = groups_post_json['record']['id']
            else:
                break


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def delete_all_groups(ind_info):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/groups'
    [groups_get_response, groups_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (groups_get_response.status_code == 200 and groups_get_json['status'] == 200), 'GET Groups response incorrect'

    groups_json_record = groups_get_json['record']
    if groups_json_record is not None:
        list_in = []
        traverse_groups.level = 1
        out_group_ids = traverse_groups(groups_json_record, list_in)
        for groupid in reversed(out_group_ids):
            if groupid != 1:
                url = 'https://' + ind_info['ip'] + ':8443/api/v1/groups' + '/' + str(groupid)
                [group_delete_response, group_delete_json] = request_delete(url, (ind_info['username'], ind_info['password']), {})
                assert (group_delete_response.status_code == 200 and group_delete_json['status'] == 200), 'DELETE Group response incorrect'


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def retrieve_group_id_by_name(ind_info, group_name):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(group_name) == str, 'Group Name is not a string'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/groups'
    [groups_get_response, groups_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (groups_get_response.status_code == 200 and groups_get_json['status'] == 200), 'GET Groups response incorrect'

    get_group_id.level = 1
    group_id_list = get_group_id(groups_get_json['record'], group_name, [])
    return group_id_list[0]


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def retrieve_root_group_name(ind_info):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/groups/1'
    [groups_get_response, groups_get_json] = request_get(url, (ind_info['username'], ind_info['password']))
    assert (groups_get_response.status_code == 200 and groups_get_json['status'] == 200), 'GET Groups response incorrect'

    return str(groups_get_json['record']['name'])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def associate_devices_to_group(ind_info, group_id, devices_id_list):
    assert (type(ind_info) == dict and sorted(list(ind_info.keys())) == sorted(ind_info_keys_list)), \
        'Credentials dictionary incorrect. Verify  correct credentials/ check ind_info_keys_list'
    assert type(group_id) == int, 'Group ID is not an int'
    assert all(isinstance(item, int) for item in devices_id_list), 'All items in ID List not ints'

    try:
        assert type(int(group_id)) == int
    except ValueError:
        return 2147483640
    assert type(devices_id_list) == list, 'Device Id List is not a list'
    assert all(isinstance(item, int) for item in devices_id_list), 'All items in ID List not ints'

    device_group_association_dict = {'ids': devices_id_list, 'groupId': int(group_id)}

    url = 'https://' + ind_info['ip'] + ':8443/api/v1/devices'

    log.info('\tAssociating Devices to Group: ' + str(group_id))
    [devices_group_put_response, devices_group_put_json] = request_put(url, (ind_info['username'], ind_info['password']),
                                                                       device_group_association_dict)
    log.info(pformat(devices_group_put_json))
    assert (devices_group_put_response.status_code == 200 and devices_group_put_json['status'] == 200), \
        'PUT Devices to Group response incorrect'


###########################################################################################################################################
###########################################################################################################################################
def traverse_groups(data, id_list):
    assert all(isinstance(item, int) for item in id_list), 'All items in ID List not ints'
    id_list.append(data['id'])
    for child_group in data['children']:
        traverse_groups.level += 1
        traverse_groups(child_group, id_list)
        traverse_groups.level -= 1
    return id_list


###########################################################################################################################################
###########################################################################################################################################
def get_group_id(data, group_name, list):
    if str(data['name']) == str(group_name):
        list.append(data['id'])
    for child_group in data['children']:
        get_group_id.level += 1
        get_group_id(child_group, group_name, list)
        get_group_id.level -= 1
    return list