# Author by Aniruddha Rajshekar
# Date: 01-20-2017
#
from ats import aetest
from ats import topology
from ats.topology import Testbed, Device, Interface, Link
from ats.topology import loader

from device_management_functions import *
from ftnm_licensing_test_functions import *

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def ftnm_licensing(self):
    log.info('\tCalling FTNM Licensing Method: ' + str(self.h_method))
    log.info('\tPrinting FTNM Licensing param_in: ' + str(self.param_in))
    param_in_dict = self.param_in
    assert type(param_in_dict) == dict, 'Parameters In is not a dictionary'

    #######################################################################################################################################
    if self.h_method == 'GETlicensingstatus':
        get_licensing_status(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETlicensefilesbyparameter':
        get_license_files_by_parameter(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETlicensefilebyserial':
        get_license_file_by_serial(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETlicensingsummary':
        get_licensing_summary(self, param_in_dict)

    #######################################################################################################################################
    else:
        self.failed('\tNo matching hMethod for FTNM Licensing')


###########################################################################################################################################
#                  COMMON SETUP SECTION
###########################################################################################################################################

class CommonSetup(aetest.CommonSetup):
    """ Common Setup for FTNM Licensing Automation Testing """

    @aetest.subsection
    def common_setup_subsection(self, testcaseid):
        log.info('\tFTNM Licensing Automation Common Setup')
        FTNMLicensingAutomation.id = testcaseid


###########################################################################################################################################
#                         TESTCASES
###########################################################################################################################################

class FTNMLicensingAutomation(aetest.Testcase):
    """ Test Case Class for FTNM Licensing Automation """

    @aetest.setup
    def ftnm_licensing_setup(self):
        """ Test Case Setup for FTNM Licensing Automation """
        log.info('\tFTNM Licensing Automation Testcase Setup')

    @aetest.test
    def run_ftnm_licensing_automation_test_case(self):
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
            if self.func_name == 'ftnm_licensing':
                log.info('\tCalling FTNM Licensing')
                ftnm_licensing(self)

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
                self.failed('\tNo matching func_name for FTNM Licensing Tests')

        except Exception as msg:
            self.failed('\tRun FTNM Licensing Test Case Failed: ' + str(msg))

    @aetest.cleanup
    def ftnm_licensing_automation_cleanup(self):
        """ Test Case Cleanup for FTNM Licensing Automation """
        log.info('\tFTNM Licensing Automation Test Case Cleanup')


################################################################################################################################################
#                       COMMON CLEANUP SECTION
###########################################################################################################################################

class CommonCleanup(aetest.CommonCleanup):
    """ Common Cleanup for FTNM Licensing Automation Testing """

    @aetest.subsection
    def common_cleanup_subsection(self, testcaseid):
        log.info('\tFTNM Licensing Automation Testing Complete')


if __name__ == '__main__':
    aetest.main()