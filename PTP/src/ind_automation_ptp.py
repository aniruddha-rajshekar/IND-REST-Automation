# Author by Aniruddha Rajshekar
# Date: 01-20-2017
#
from ats import aetest
from ats import topology
from ats.topology import Testbed, Device, Interface, Link
from ats.topology import loader

from ptp_test_functions import *

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def ptp(self):
    log.info('\tCalling PTP Method: ' + str(self.h_method))
    log.info('\tPrinting PTP param_in: ' + str(self.param_in))
    param_in_dict = self.param_in
    assert type(param_in_dict) == dict, 'Parameters In is not a dictionary'

    #######################################################################################################################################
    if self.h_method == 'GETptptopologybygroup':
        get_ptp_topology_by_group(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETptpnodesummarybyid':
        get_ptp_node_summary_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETptpdomainsummarybyid':
        get_ptp_domain_summary_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTptpgmoffsetthresholdbyid':
        put_ptp_gm_offset_threshold_by_id(self, param_in_dict)

    #######################################################################################################################################
    else:
        self.failed('\tNo matching hMethod for PTP')


###########################################################################################################################################
#                  COMMON SETUP SECTION
###########################################################################################################################################

class CommonSetup(aetest.CommonSetup):
    """ Common Setup for PTP Automation Testing """

    @aetest.subsection
    def common_setup_subsection(self, testcaseid):
        log.info('\tPTP Automation Common Setup')
        PTPAutomation.id = testcaseid


###########################################################################################################################################
#                         TESTCASES
###########################################################################################################################################

class PTPAutomation(aetest.Testcase):
    """ Test Case Class for PTP Automation """

    @aetest.setup
    def ptp_setup(self):
        """ Test Case Setup for PTP Automation """
        log.info('\tPTP Automation Testcase Setup')

    @aetest.test
    def run_ptp_automation_test_case(self):
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
            if self.func_name == 'ptp':
                log.info('\tCalling PTP')
                ptp(self)

            elif self.func_name == 'device_discovery':
                log.info('\tCalling Device Discovery')
                discovery_profile_file = self.param_in['discovery_profile_file']
                if type(discovery_profile_file) is not list:
                    discovery_profile_file = [discovery_profile_file]

                access_profile_file = self.param_in['access_profile_file']
                if type(access_profile_file) is not list:
                    access_profile_file = [access_profile_file]

                clear_all(self.ind_info['ip'], self.username_in, self.password_in)
                for i in range(0, len(discovery_profile_file)):
                    ip_scan_discovery(self.ind_info['ip'], self.username_in, self.password_in, discovery_profile_file[i],
                                      access_profile_file[i], False)

            elif self.func_name == 'cleanup':
                log.info('\tCalling Clear All')
                clear_all(self.ind_info['ip'], self.username_in, self.password_in)

            else:
                self.failed('\tNo matching func_name for PTP Tests')

        except Exception as msg:
            self.failed('\tRun PTP Test Case Failed: ' + str(msg))

    @aetest.cleanup
    def ptp_automation_cleanup(self):
        """ Test Case Cleanup for PTP Automation """
        log.info('\tPTP Automation Test Case Cleanup')


###########################################################################################################################################
#                       COMMON CLEANUP SECTION
###########################################################################################################################################

class CommonCleanup(aetest.CommonCleanup):
    """ Common Cleanup for PTP Automation Testing """

    @aetest.subsection
    def common_cleanup_subsection(self, testcaseid):
        log.info('\tPTP Automation Testing Complete')


if __name__ == '__main__':
    aetest.main()