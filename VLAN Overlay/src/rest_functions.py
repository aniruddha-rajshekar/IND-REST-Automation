import requests
import inspect
import logging
log = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


###########################################################################################################################################
###########################################################################################################################################
def request_get(url, auth_info):
    assert type(url) == str, 'URL not a string'
    assert type(auth_info) == tuple, 'Auth info not a tuple'
    try:
        request_data = requests.request('GET', str(url), auth=auth_info, verify=False, headers={'Content-Type': 'application/json'})
        return [request_data, request_data.json()]
    except Exception as msg:
        log.info(str(inspect.stack()[0][3]) + ': ' + str(msg))
        return [requests.get('http://httpbin.org/status/500'), {}]


###########################################################################################################################################
###########################################################################################################################################
def request_post(url, auth_info, data):
    assert type(url) == str, 'URL not a string'
    assert type(auth_info) == tuple, 'Auth info not a tuple'
    # assert type(data) == dict, 'Data not a dictionary'
    try:
        request_data = requests.request('POST', str(url), auth=auth_info, verify=False, json=data,
                                        headers={'Content-Type': 'application/json'})
        return [request_data, request_data.json()]
    except Exception as msg:
        log.info(str(inspect.stack()[0][3]) + ': ' + str(msg))
        return [requests.get('http://httpbin.org/status/500'), {}]


###########################################################################################################################################
###########################################################################################################################################
def request_put(url, auth_info, data):
    assert type(url) == str, 'URL not a string'
    assert type(auth_info) == tuple, 'Auth info not a tuple'
    assert type(data) == dict, 'Data not a dictionary'
    try:
        request_data = requests.request('PUT', str(url), auth=auth_info, verify=False, json=data,
                                        headers={'Content-Type': 'application/json'})
        return [request_data, request_data.json()]
    except Exception as msg:
        log.info(str(inspect.stack()[0][3]) + ': ' + str(msg))
        return [requests.get('http://httpbin.org/status/500'), {}]


###########################################################################################################################################
###########################################################################################################################################
def request_delete(url, auth_info, data):
    assert type(url) == str, 'URL not a string'
    assert type(auth_info) == tuple, 'Auth info not a tuple'
    assert type(data) == dict, 'Data not a dictionary'
    try:
        request_data = requests.request('DELETE', str(url), auth=auth_info, verify=False, json=data,
                                        headers={'Content-Type': 'application/json'})
        return [request_data, request_data.json()]
    except Exception as msg:
        log.info(str(inspect.stack()[0][3]) + ': ' + str(msg))
        return [requests.get('http://httpbin.org/status/500'), {}]