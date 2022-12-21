# Author by Aniruddha Rajshekar
# Date: 01-20-2017
#
from ats import aetest
from ats import topology
from ats.topology import Testbed, Device, Interface, Link
from ats.topology import loader

from device_management_functions import *
from device_management_test_functions import *

log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def device_management(self):
    log.info('\tCalling Device Management Method: ' + str(self.h_method))
    log.info('\tPrinting Device Management param_in: ' + str(self.param_in))
    param_in_dict = self.param_in
    assert type(param_in_dict) == dict, 'Parameters In is not a dictionary'

    #######################################################################################################################################
    if self.h_method == 'POSTdevicerefresh':
        post_on_demand_refresh(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'DELETEdevices':
        delete_devices(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'DELETEaccessprofiles':
        delete_access_profiles(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'POSTdevicesstatechange':
        post_devices_state_change(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETdevicesadminstates':
        get_devices_admin_states(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETdevicebyid':
        get_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETdevicesbyparameter':
        get_devices_by_parameter(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETdeviceportconfigmetabyid':
        get_device_port_config_meta_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'POSTdeviceportconfig':
        post_device_port_config(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETdevicesexport':
        get_devices_export(self, param_in_dict)

    #######################################################################################################################################
    else:
        self.failed('\tNo matching hMethod for Device Management')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def supported_device_management(self):
    log.info('\tCalling Supported Device Management Method: ' + str(self.h_method))
    log.info('\tPrinting Supported Device Management param_in: ' + str(self.param_in))
    param_in_dict = self.param_in
    assert type(param_in_dict) == dict, 'Parameters In is not a dictionary'

    #######################################################################################################################################
    if self.h_method == 'GETsupporteddevicesbyparameter':
        get_supported_devices_by_parameter(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETsupporteddevicebyid':
        get_supported_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    else:
        self.failed('\tNo matching hMethod for Supported Device Management')


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def inventory_dashboard_management(self):
    log.info('\tCalling Inventory-Dashboard Management Method: ' + str(self.h_method))
    log.info('\tPrinting Inventory-Dashboard param_in: ' + str(self.param_in))
    param_in_dict = self.param_in

    #######################################################################################################################################
    if self.h_method == 'GETalarmssummaryaffecteddevicesbygroup':
        get_alarms_summary_affected_devices_by_group(self, param_in_dict)


###########################################################################################################################################
###########################################################################################################################################
@handle_exception_wrapper
def other_device_management(self):
    log.info('\tCalling Other Device Management Method: ' + str(self.h_method))
    log.info('\tPrinting Other Device Management param_in: ' + str(self.param_in))
    param_in_dict = self.param_in

    #######################################################################################################################################
    if self.h_method == 'GETotherdevicesbyparameter':
        get_other_devices_by_parameter(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETcipdevicetypes':
        get_other_device_types(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETprofinetdevicetypes':
        get_other_device_types(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETopcuadevicetypes':
        get_other_device_types(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETsnmpdevicetypes':
        get_other_device_types(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETmodbusdevicetypes':
        get_other_device_types(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETbacnetdevicetypes':
        get_other_device_types(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETcipdevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETprofinetdevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETopcuadevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETnetbiosdevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETsnmpdevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETunknowndevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETmodbusdevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETbacnetdevicebyid':
        get_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTcipdevicebyid':
        put_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTprofinetdevicebyid':
        put_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTopcuadevicebyid':
        put_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTsnmpdevicebyid':
        put_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTmodbusdevicebyid':
        put_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'PUTbacnetdevicebyid':
        put_other_device_by_id(self, param_in_dict)

    #######################################################################################################################################
    elif self.h_method == 'GETotherdevicesconnecteddevicesbyid':
        get_other_devices_connected_devices_by_id(self, param_in_dict)

    #######################################################################################################################################
    else:
        self.failed('\tNo matching hMethod for Other Device Management')


###########################################################################################################################################
#                  COMMON SETUP SECTION
###########################################################################################################################################

class CommonSetup(aetest.CommonSetup):
    """ Common Setup for Device Management Automation Testing """

    @aetest.subsection
    def common_setup_subsection(self, testcaseid):
        log.info('\tDevice Management Automation Common Setup')
        DeviceManagementAutomation.id = testcaseid


###########################################################################################################################################
#                         TESTCASES
###########################################################################################################################################

class DeviceManagementAutomation(aetest.Testcase):
    """ Test Case Class for Device Management Automation """

    @aetest.setup
    def device_management_setup(self):
        """ Test Case Setup for Device Management Automation """
        log.info('\tDevice Management Automation Testcase Setup')

    @aetest.test
    def run_device_management_automation_test_case(self):
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
            if self.func_name == 'supported_device_management':
                log.info('\tCalling Supported Device Management')
                supported_device_management(self)

            elif self.func_name == 'device_management':
                log.info('\tCalling Device Management')
                device_management(self)

            elif self.func_name == 'other_device_management':
                log.info('\tCalling Other Device Management')
                other_device_management(self)

            elif self.func_name == 'inventory_dashboard_management':
                log.info('\tCalling Inventory-Dashboard Management')
                inventory_dashboard_management(self)

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
                self.failed('\tNo matching func_name for Device Management Tests')

        except Exception as msg:
            self.failed('\tRun Device Management Test Case Failed: ' + str(msg))

    @aetest.cleanup
    def device_management_automation_cleanup(self):
        """ Test Case Cleanup for Device Management Automation """
        log.info('\tDevice Management Automation Test Case Cleanup')


###########################################################################################################################################
#                       COMMON CLEANUP SECTION
###########################################################################################################################################

class CommonCleanup(aetest.CommonCleanup):
    """ Common Cleanup for Device Management Automation Testing """

    @aetest.subsection
    def common_cleanup_subsection(self, testcaseid):
        log.info('\tDevice Management Automation Testing Complete')


if __name__ == '__main__':
    aetest.main()