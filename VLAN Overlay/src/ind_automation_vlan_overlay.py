# Author by Aniruddha Rajshekar
# Date: 02-19-2018
#
from ats import aetest
from ats import topology
from ats.topology import Testbed, Device, Interface, Link
from ats.topology import loader

from device_management_functions import *
from vlan_overlay_test_functions import *

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def vlan_overlay(self):
    log.info('\tCalling Vlan Overlay Management Method: ' + str(self.h_method))
    log.info('\tPrinting Vlan Overlay Management param_in: ' + str(self.param_in))
    param_in_dict = self.param_in
    assert type(param_in_dict) == dict, 'Parameters In is not a dictionary'

    #######################################################################################################################################
    if self.h_method == 'GETvlansbygroup':
        get_vlans_by_group(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETtopologyvlansbygroup':
        get_topology_vlans_by_group(self, param_in_dict)

    #######################################################################################################################################
    else:
        self.failed('\tNo matching hMethod for Vlan Overlay Management')


###########################################################################################################################################
#                  COMMON SETUP SECTION
###########################################################################################################################################

class CommonSetup(aetest.CommonSetup):
    """ Common Setup for Vlan Overlay Automation Testing """

    @aetest.subsection
    def common_setup_subsection(self, testcaseid):
        log.info('\tVlan Overlay Automation Common Setup')
        VlanOverlayAutomation.id = testcaseid


###########################################################################################################################################
#                         TESTCASES
###########################################################################################################################################

class VlanOverlayAutomation(aetest.Testcase):
    """ Test Case Class for Vlan Overlay Automation """

    @aetest.setup
    def vlan_overlay_setup(self):
        """ Test Case Setup for Vlan Overlay Automation """
        log.info('\tVlan Overlay Automation Testcase Setup')

    @aetest.test
    def run_vlan_overlay_automation_test_case(self):
        self.h_method = self.parameters['testcasename']

        try:
            self.api_args = self.parameters['restapi']
            self.url_path = self.api_args['url']
            self.func_name = self.api_args['funcName']
            self.param_in = self.api_args['paramIn']
            self.password_in = self.api_args['passwordIn']
            self.username_in = self.api_args['usernameIn']
            self.expected_in = self.api_args['expectedIn']
            self.ind_info = {'ip': str(re.findall(r'[0-9]+(?:\.[0-9]+){3}', self.url_path)[0]), 'username': str(self.username_in),
                             'password': str(self.password_in)}
            expected_in_val = self.api_args['expectedIn']
            if type(expected_in_val) is not list:
                self.expected_in = [expected_in_val]

            log.info('\tCall function is:')
            if self.func_name == 'vlan_overlay':
                log.info('\tCalling Vlan Overlay Management')
                vlan_overlay(self)

            elif self.func_name == 'device_discovery':
                log.info('\tCalling Device Discovery')
                discovery_profile_file = self.param_in['discovery_profile_file']
                if type(discovery_profile_file) is not list:
                    discovery_profile_file = [discovery_profile_file]

                access_profile_file = self.param_in['access_profile_file']
                if type(access_profile_file) is not list:
                    access_profile_file = [access_profile_file]

                if self.param_in['clear_all'] == 'True':
                    clear_all(self.ind_info['ip'], self.username_in, self.password_in)
                for i in range(0, len(discovery_profile_file)):
                    ip_scan_discovery(self.ind_info['ip'], self.username_in, self.password_in, discovery_profile_file[i],
                                      access_profile_file[i], False)

            elif self.func_name == 'cleanup':
                log.info('\tCalling Clear All')
                clear_all(self.ind_info['ip'], self.username_in, self.password_in)

            else:
                self.failed('\tNo matching func_name for Vlan Overlay Tests')

        except Exception as msg:
            self.failed('\tRun Vlan Overlay Test Case Failed: ' + str(msg))

    @aetest.cleanup
    def vlan_overlay_automation_cleanup(self):
        """ Test Case Cleanup for Vlan Overlay Automation """
        log.info('\tVlan Overlay Automation Test Case Cleanup')


###########################################################################################################################################
#                       COMMON CLEANUP SECTION
###########################################################################################################################################

class CommonCleanup(aetest.CommonCleanup):
    """ Common Cleanup for Vlan Overlay Automation Testing """

    @aetest.subsection
    def common_cleanup_subsection(self, testcaseid):
        log.info('\tVlan Overlay Automation Testing Complete')


if __name__ == '__main__':
    aetest.main()