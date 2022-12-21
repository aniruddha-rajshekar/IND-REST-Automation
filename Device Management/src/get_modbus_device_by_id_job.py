# Author by Aniruddha Rajshekar
# Date: 01-20-2017

import os
from ats.easypy import run
from ats import aetest
from ats import topology
from ats.topology import Testbed, Device, Interface, Link
from ats.topology import loader
from common_functions import *

log = logging.getLogger(__name__)


###########################################################################################################################################
###########################################################################################################################################
def main():
    test_path = (os.path.dirname(os.path.abspath(__file__)))
    ##
    try:
        ind_status_message_dict = read_dict_data()
        log.info(pformat(ind_status_message_dict))
        testbed = loader.load(test_path + '/get_modbus_device_by_id.yaml')

        # Confirming that this is indeed a testbed object
        log.info('\tTopology ' + repr(type(testbed) is topology.Testbed))

        log.info(repr('S8000-108' in testbed))
        log.info(testbed.devices)
        s8000 = testbed.devices['S8000-108']
        func_name = ''
        url = ''
        param_in = ''
        h_method = ''
        password_in = ''
        username_in = ''
        expected_in = ''
        test_case_id = ''
        for key1 in sorted(s8000.custom):

            log.info('\tLevel 1 Key and Value ==> ' + (str(key1)) + ':::::' + str(s8000.custom[key1]))

            for key2 in s8000.custom[key1]:
                log.info('\tLevel 2 Key and Value ==> ' + str(key2) + ':::::' + str(s8000.custom[key1][key2]))

                if key2 == 'function':
                    func_name = s8000.custom[key1]['function']

                if key2 == 'entity_title':
                    test_case_id = s8000.custom[key1]['entity_title']

                if key2 == 'http_method':
                    h_method = s8000.custom[key1]['http_method']

                if key2 == 'url':
                    url = s8000.custom[key1]['url']

                if key2 == 'parameter':
                    param_in = s8000.custom[key1]['parameter']

                if key2 == 'login':
                    username_in = s8000.custom[key1]['login']

                if key2 == 'password':
                    password_in = s8000.custom[key1]['password']

                if key2 == 'expected':
                    expected_in = s8000.custom[key1]['expected']

            run(testscript=test_path + '/ind_automation_device_management.py', testcasename=h_method, testcaseid=test_case_id,
                restapi={'funcName': func_name, 'url': url, 'paramIn': param_in, 'usernameIn': username_in,
                         'passwordIn': password_in, 'expectedIn': expected_in})

    except Exception as msg:
        log.info('\tGET Modbus Device By ID Job Failed: ' + str(msg))