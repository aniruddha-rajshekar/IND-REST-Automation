from common_functions import *
from device_management_functions import *

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_license_files_by_parameter(self, param_in_dict):
    log.info('\tPerforming GET All License files by Parameter')
    limit_val = 2147483640
    offset_val = 0

    if 'limit' not in param_in_dict:
        self.failed('\tLimit value missing')
    if 'offset' not in param_in_dict:
        self.failed('\tOffset value missing')

    if param_in_dict['limit'] != 'null':
        limit_val = param_in_dict['limit']
    if param_in_dict['offset'] != 'null':
        offset_val = param_in_dict['offset']

    url = self.url_path + '?limit=' + str(limit_val) + '&offset=' + str(offset_val)
    log.info('\tGET License files by parameter URL: ' + str(url))

    [license_files_get_response, license_files_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET All By Parameter Result')
    log.info(pformat(license_files_get_json))
    log.info('\tStatus Code: ' + str(license_files_get_json['status']))

    if str(license_files_get_json['status']) != '200':
        verify_pass_or_fail_status_code(self, self.h_method, license_files_get_json['status'], self.expected_in[0])
    else:
        verify_pass_or_fail_status_code(self, self.h_method, license_files_get_json['status'], '200')
        verify_pass_or_fail_get_all(self, self.h_method, license_files_get_json['status'], self.expected_in[0], license_files_get_json)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_licensing_status(self, param_in_dict):
    log.info('\tPerforming GET Licensing status')

    if 'status_string' not in param_in_dict:
        self.failed('\tLicense Status string missing')
    if 'status' not in param_in_dict:
        self.failed('\tLicense Status value missing')

    url = self.url_path
    [licensing_status_get_response, licensing_status_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Licensing status Result')
    log.info(pformat(licensing_status_get_json))
    log.info('\tStatus Code: ' + str(licensing_status_get_json['status']))

    verify_pass_or_fail_status_code(self, self.h_method, licensing_status_get_json['status'], self.expected_in[0])

    assert licensing_status_get_json['record']['licenseStatusStr'] == param_in_dict['status_string'], 'License Status string incorrect'
    assert int(licensing_status_get_json['record']['licenseStatus']) == int(param_in_dict['status']), \
        'License Status value incorrect'


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_license_file_by_serial(self, param_in_dict):
    log.info('\tPerforming GET License file by Serial Number')

    if 'serial_number' not in param_in_dict:
        self.failed('\tLicense file Serial Number missing')

    serial_number = param_in_dict['serial_number']
    log.info('\tSerial Number for GET License file by Serial Number ' + str(serial_number))

    url = self.url_path + '/' + str(serial_number)
    [license_serial_get_response, license_serial_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET License file by Serial Number Result')
    log.info(pformat(license_serial_get_json))
    log.info('\tStatus Code: ' + str(license_serial_get_json['status']))

    time.sleep(0.5)
    verify_pass_or_fail_status_code(self, self.h_method, license_serial_get_json['status'], self.expected_in[0])


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def get_licensing_summary(self, param_in_dict):
    log.info('\tPerforming GET Licensing Summary')

    if 'featureName' not in param_in_dict:
        self.failed('\tLicense summary Feature Name missing')
    if 'available' not in param_in_dict:
        self.failed('\tLicense summary Available count missing')
    if 'used' not in param_in_dict:
        self.failed('\tLicense summary Used count missing')
    if 'add_devices' not in param_in_dict:
        self.failed('\tAdd Devices missing')
    if 'task_message' not in param_in_dict:
        self.failed('\tTask Message missing')

    if param_in_dict['add_devices'] == 'False':
        clear_all(self.ind_info['ip'], self.ind_info['username'], self.ind_info['password'])

    if param_in_dict['add_devices'] == 'True':
        del_ip_list = [retrieve_device_info_by_ip(self.ind_info, ip, 'id', False) for ip in ['100.100.100.60']]
        if all(isinstance(item, int) for item in del_ip_list):
            delete_unsupported_or_notapplicable_by_id(self.ind_info, del_ip_list)

        url = 'https://' + self.ind_info['ip'] + ':8443/api/v1/devices'
        [devices_get_response, devices_get_json] = request_get(url, (self.ind_info['username'], self.ind_info['password']))
        assert (devices_get_response.status_code == 200 and devices_get_json['status'] == 200), \
            'GET Devices response incorrect'
        id_list_unlicensed = [devices_get_json['records'][i]['id'] for i in range(0, devices_get_json['recordCount'])
                              if devices_get_json['records'][i]['deviceAdminStateStr'] == 'Unlicensed']

        unlicensed_count = len(id_list_unlicensed)
        post_message = change_state(self.ind_info,id_list_unlicensed, 'Licensed')
        log.info('State change POST message is: ' + str(post_message))

    url = self.url_path
    [licensing_summary_get_response, licensing_summary_get_json] = request_get(url, (self.username_in, self.password_in))

    log.info('\tPrinting GET Licensing Summary Result')
    log.info(pformat(licensing_summary_get_json))
    log.info('\tStatus Code: ' + str(licensing_summary_get_json['status']))

    verify_pass_or_fail_status_code(self, self.h_method, licensing_summary_get_json['status'], self.expected_in[0])

    license_avail_count = [licensing_summary_get_json['record']['licenseSummary'][i]['available']
                           for i in range(0, len(licensing_summary_get_json['record']['licenseSummary']))
                           if param_in_dict['featureName'] == licensing_summary_get_json['record']['licenseSummary'][i]['featureName']][0]

    license_used_count = [licensing_summary_get_json['record']['licenseSummary'][i]['used']
                          for i in range(0, len(licensing_summary_get_json['record']['licenseSummary']))
                          if param_in_dict['featureName'] == licensing_summary_get_json['record']['licenseSummary'][i]['featureName']][0]

    if param_in_dict['task_message'] != 'null':
        if param_in_dict['task_message'].count('{}') == 1:
            log.info('\tExpected task message: ' + str(param_in_dict['task_message']).format(str(param_in_dict['used'])))
            log.info('\tActual task message:   ' + str(post_message))
            assert str(param_in_dict['task_message']).format(str(param_in_dict['used'])) == str(post_message), \
                'State change task message incorrect'
        elif param_in_dict['task_message'].count('{}') == 2:
            if unlicensed_count > param_in_dict['used']:
                log.info('\tExpected task message: ' + str(param_in_dict['task_message']).format(str(param_in_dict['used']),
                                                                                                 str(unlicensed_count)))
                log.info('\tActual task message:   ' + str(post_message))
                assert str(param_in_dict['task_message']).format(str(param_in_dict['used']), str(unlicensed_count)) == str(post_message), \
                'State change task message incorrect'
            else:
                log.info('\tExpected task message: ' + str(param_in_dict['task_message']).format(str(param_in_dict['available']),
                                                                                                 str(unlicensed_count)))
                log.info('\tActual task message:   ' + str(post_message))
                assert str(param_in_dict['task_message']).format(str(param_in_dict['available']), str(unlicensed_count)) == \
                       str(post_message), 'State change task message incorrect'

    assert int(license_avail_count) == int(param_in_dict['available']), 'Licenses Available count incorrect'
    assert int(license_used_count) == int(param_in_dict['used']), 'Licenses Used count incorrect'