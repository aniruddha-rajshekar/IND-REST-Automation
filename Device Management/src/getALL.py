'''
Created on Dec 14, 2015

@author: poornika
'''
############################# Python Libraries  ####################################################

from requests import packages
import logging, os
import requests
import time
from pprint import pprint
import csv
from datetime import date, datetime
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
from time import sleep
import io
import urllib3
import zipfile
from random import shuffle
############################  LOGGING PARAMETERS ###################################################
systemLog = logging.getLogger(__name__)
cwd = os.getcwd()
logging.basicConfig(level=logging.DEBUG,
                    filename=cwd + "/ScaleLog.csv",
                    filemode="a+",
                    format="")

################################SYSTEM VARIABLES####################################################
requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


################################SCRIPT####################################################
class Alarm(object):
    def __init__(self, eventType, ipAddress, eventProperties):
        self.eventType = eventType
        self.ipAddress = ipAddress
        self.eventProperties = eventProperties

    def __str__(self):
        return ("User object:\n"
                "  eventType = {0}\n"
                "  ipAddress = {1}\n"
                "  eventProperties = {2}"
                .format(self.eventType, self.ipAddress, self.eventProperties))


def Post(Category, hMethod, urlPath, paramIn, usernameIn, passwordIn, expectedIn):
    dictA = paramIn
    authentication = (usernameIn, passwordIn)
    headers = {'Content-Type': 'application/json'}
    starttime = datetime.now()
    # print(starttime)
    try:
        req = requests.post(urlPath, json=dictA, headers=headers, verify=False, auth=authentication)
        # print(req.content)
    except requests.exceptions.ConnectionError:
        print(str(starttime) + ' ,ERROR ,' + Category + ' ,' + hMethod + ' ,requests.exceptions.ConnectionError')
        return
    endtime = datetime.now()
    retrivaltime = endtime - starttime
    responseBody = req.json()
    # pprint(responseBody)
    if responseBody["status"] == expectedIn:
        # systemLog.info(str(starttime) + ' ,INFO ,' + Category + ' ,' + hMethod + ' ,' + str(retrivaltime))
        if hMethod == "POSTlocalbackup":
            global taskID
            taskID = responseBody["record"]["taskId"]
        return
    else:
        print(str(starttime) + ' ,ERROR ,' + Category + ' ,' + hMethod + ' ,' + str(retrivaltime) + ' ,' + responseBody["message"])


def Get(Category, hMethod, urlPath, usernameIn, passwordIn, expectedIn):
    authentication = (usernameIn, passwordIn)
    headers = {'Content-Type': 'application/json'}
    starttime = datetime.now()
    try:
        req = requests.get(urlPath, headers=headers, verify=False, auth=authentication)
    except requests.exceptions.ConnectionError:
        systemLog.info(str(starttime) + ' ,ERROR ,' + Category + ' ,' + hMethod + ' ,requests.exceptions.ConnectionError')
        return
    endtime = datetime.now()
    retrivaltime = endtime - starttime
    if req.headers['content-type'] == "application/json;charset=UTF-8":
        responseBody = req.json()
    elif req.headers['content-type'] == "application/x-zip-compressed; charset=UTF-8":
        systemLog.info(str(starttime) + ' ,INFO ,' + Category + ' ,' + hMethod + ' ,' + str(retrivaltime))
        return req

    if responseBody["status"] == expectedIn:
        if hMethod == "GETtasksid":
            if responseBody["record"]["stateStr"] == 'Preparing' or 'Running' or 'Scheduled':
                sleep(5)
                Get(Category, "GETtask", urlPath, usernameIn, passwordIn, expectedIn)
            elif responseBody["record"]["stateStr"] == 'Failed':
                systemLog.info(str(starttime) + ' ,ERROR ,' + Category + ' ,' + hMethod + ' ,' + str(retrivaltime) + ' ,' + 'Task Failed')
                return
            elif responseBody["record"]["stateStr"] == 'Completed':
                taskTime = responseBody["record"]["startTime"] - responseBody["record"]["endTime"]
                systemLog.info(responseBody["record"]["startTimeStr"] + ' ,INFO ,' + Category + ' ,' + hMethod + ' ,' + str(
                    datetime.fromtimestamp(taskTime)))
                return
        systemLog.info(str(starttime) + ' ,INFO ,' + Category + ' ,' + hMethod + ' ,' + str(retrivaltime))
        return
    else:
        systemLog.info(str(starttime) + ' ,ERROR ,' + Category + ' ,' + hMethod + ' ,' + str(retrivaltime) + ' ,' + responseBody["message"])


def Generate_Events(urlPath, UserName, PassWord, device_ip, alarm_type):
    eventType = {alarm_type}
    eventProperties = {"test prop": "some value"}

    for event in eventType:
        values = []
        values.append(event)
        values.append(str(device_ip))
        values.append(eventProperties)
        item = Alarm(*values)
        Post('Events', 'POSTeventsgenerate', urlPath, item.__dict__, UserName, PassWord, 200)


def getAlarmsEvents(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("Events", "GETeventsall", C7RURL + "events", UserName, PassWord, 200)
    Get("Alarms", "GETalarmsall", C7RURL + "alarms", UserName, PassWord, 200)


def generateEvents(C7RIp, UserName, PassWord, device_ip, alarm_type):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Generate_Events(C7RURL + "events", UserName, PassWord, device_ip, alarm_type)


def getAuditTrail(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("AAA", "GETAuditTrail", C7RURL + "audit-trails?limit=100&offset=0", UserName, PassWord, 200)


def Download_log(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    C7R_Response = Get("LOGGING", "GETsystemlog", C7RURL + "logs", UserName, PassWord, 200)
    z = zipfile.ZipFile(io.BytesIO(C7R_Response.content))
    FileList = z.namelist()
    if not "application.log" in FileList:
        systemLog.info(str(datetime.now()) + ' ,ERROR ,' + "LOGGING ," + "GETsystemlog ," + str(
            datetime.now() - datetime.now()) + ' ,' + "Zip file has not been downloaded correctly. Application.log not found")


def On_Demand_BackUp(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Post("BACKUPS", "POSTlocalbackup", C7RURL + "backups/tasks", None, UserName, PassWord, 200)
    if taskID != None:
        Get("BACKUPS", "GETtasksid", C7RURL + "tasks/" + str(taskID), UserName, PassWord, 200)


def getTopology(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("TOPOLOGY", "GETTopology", C7RURL + "topology", UserName, PassWord, 200)


def postTopology(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Post("TOPOLOGY", "POSTTopology", C7RURL + "topology/discoveries/tasks", None, UserName, PassWord, 200)


def getAllTasks(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("TASKS", "GETTasks", C7RURL + "tasks", UserName, PassWord, 200)


def getNetworkInventory(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("INVENTORY", "GETNetworkInventory", C7RURL + "network-devices-inventory?limit=100&offset=0", UserName, PassWord, 200)


def getClientInventory(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("INVENTORY", "GETClientInventory", C7RURL + "client-devices?limit=100&offset=0&direction=ASC", UserName, PassWord, 200)


def getDevicesWithGroups(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("INVENTORY", "GETGroupInventory", C7RURL + "devices?groupId=1&limit=100&offset=0", UserName, PassWord, 200)


def getPortSummary(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("DASHBOARD", "GETPortSummary", C7RURL + "ports-summary?groupId=1", UserName, PassWord, 200)


def getNetworkTrafficUtil(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("DASHBOARD", "GETNetworkUtil", C7RURL + "network-devices-traffic-util-summary?groupId=1", UserName, PassWord, 200)


def getPortUtil(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("DASHBOARD", "GETPortUtil", C7RURL + "ports-traffic-util-summary?groupId=1", UserName, PassWord, 200)


def getAssetSummary(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("DASHBOARD", "GETAssetSummary", C7RURL + "asset-summary?groupId=1", UserName, PassWord, 200)


def getGroups(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("GROUPS", "GETGroups", C7RURL + "groups-tree-view", UserName, PassWord, 200)


def getUsers(C7RIp, UserName, PassWord):
    C7RURL = "https://" + C7RIp + ":8443/api/v1/"
    Get("USERS", "GETUsers", C7RURL + "users", UserName, PassWord, 200)

# if __name__ == '__main__':
#   GETAlarms_Events("10.195.119.49", "systemadmin", "Admin123#")
#   Generate_AlarmsEvents("10.195.119.49", "systemadmin", "Admin123#")
#   Audit_Trail("10.195.119.49", "systemadmin", "Admin123#")
#   Download_log("10.195.119.49","systemadmin", "Admin123#")
#   On_Demand_BackUp("10.195.119.49","systemadmin", "Admin123#")
