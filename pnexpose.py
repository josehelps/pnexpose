#!/bin/python

import urllib2
from lxml import etree
from lxml import objectify
import random
import base64
import ssl

print_query = False

#Dump Object Function
def dump(obj):
  for attr in dir(obj):
      print "obj.%s = %s" % (attr, getattr(obj, attr))
      
#Request parser
def request(connection, call, parameters={}, appendelements=[]):
    """ Processes a Request for an API call """
    xml = etree.Element(call + "Request")

    #if it has a token it adds it to the request 
    if(connection.authtoken != ''):
        xml.set('session-id',connection.authtoken)
        xml.set('sync-id', str(random.randint(1,65535)))

    #parses parameters from calls
    for param,value in parameters.iteritems():
        xml.set(param, str(value))
    
    for el in appendelements:
        xml.append(el)
    
    #makes request and returns response
    data=etree.tostring(xml)
    request = urllib2.Request(connection.url + connection.api, data)
    request.add_header('Content-Type', 'text/xml')
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    response = urllib2.urlopen(request, context=gcontext)
    response = etree.XML(response.read())
    return response
        

class SiteSummary():
    def __init__(self, description, id, name, riskfactor, riskscore):
        self.description = description
        self.id = int(id)
        self.name = str(name)
        self.riskfactor = float(riskfactor)
        self.riskscore = str(riskscore)
        
class Site():    
    def __init__(self, nameOrConn, templateOrID):
        if nameOrConn.authtoken:
            response = request(nameOrConn, "SiteConfig", {"site-id" : templateOrID})
            siteData = objectify.fromstring(etree.tostring(response))
            siteProperties = dict(siteData.Site.items())
            self.id = int(siteProperties['id'])
            self.name = siteProperties['name']
            self.description = siteProperties['description']
            self.riskfactor = float(siteProperties['riskfactor'])
            self.isDynamic = siteProperties['isDynamic']
            self.assets = list(siteData.Site.Hosts.host)
        else:
            self.name = nameOrConn
            self.scan_template = templateOrID
        
class EngineSummary():
    def __init__(self, id, name, address, port, status, scope):
        self.id = int(id)
        self.name = str(name)
        self.address = str(address)
        self.port = int(port)
        self.status = str(status)
        self.scope = str(scope)

class Tasks():
    def __init__(self, active, completed, pending):
        self.active = int(active)
        self.completed = int(completed)
        self.pending = int(pending)
        
class Nodes():
    def __init__(self, filtered, live, unresolved, other, dead):
        self.filtered = int(filtered)
        self.live = int(live)
        self.unresolved = int(unresolved)
        self.other = int(other)
        self.dead = int(dead)
        
class Vulnerability():
    def __init__(self, status, count, severity = 0):
        self.status = status
        self.count = int(count)
        self.severity = int(severity)
        
class ScanSummary():        
    def __init__(self, scanid, siteid, engineid, name, status, tasks, nodes, vulns, startTime, endTime = None):
        self.scanid = int(scanid)
        self.siteid = int(siteid)
        self.engineid = int(engineid)
        self.name = name
        self.status = status
        self.startTime = startTime
        self.endTime = endTime
        self.tasks = tasks
        self.nodes = nodes
        self.vulns = vulns

class UserSummary():
    def __init__(self, id, authSource, authModule, userName, fullName, email, administrator, disabled, locked, siteCount, groupCount):
        self.id = int(id)
        self.authSource = authSource
        self.authModule = authModule
        self.userName = userName
        self.fullName = fullName
        self.email = email
        self.administrator = int(administrator)
        self.disabled = int(disabled)
        self.locked = int(locked)
        self.siteCount = int(siteCount)
        self.groupCount = int(groupCount)
        
class User():
    def __init__(self, id, rolename, authsrcid, name, fullname, email, enabled):
        self.id = int(id)
        self.rolename = rolename
        self.authsrcid = authsrcid
        self.name = name
        self.fullname = fullname
        self.email = email
        self.enabled = bool(enabled)
        
        # There is currently no way to retrieve the list of sites that a user has access to via the Nexpose API.
        # The methods in the official Nexpose Ruby Gem default to showing True for allSites/allGroups access
        # if the role name is 'global-admin' and False if not. This does the same thing, but you can set these
        # values manually before saving if needed.
        if self.rolename == "global-admin":
            self.allSites = True
            self.allGroups = True
        else:
            self.allSites = False
            self.allGroups = False
            
        
    def save(self, conn):
        userconfig = etree.Element("UserConfig")
        userconfig.set("id", str(self.id))
        userconfig.set("role-name", self.rolename)
        userconfig.set("authsrcid", str(self.authsrcid))
        userconfig.set("name", self.name)
        userconfig.set("fullname", self.fullname)
        userconfig.set("email", self.email)
        userconfig.set("enabled", str(int(self.enabled)))
        userconfig.set("allSites", str(self.allSites))
        userconfig.set("allGroups", str(self.allGroups))

        print etree.tostring(userconfig)
        response = request(conn, "UserSave", appendelements=[userconfig])
        return response
        
# Creates class for the client
class Connection():
    def __init__(self, server, port, username, password):
        """ Connection Class init call """
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.url = 'https://{0}:{1}'.format(self.server,self.port)
        self.api = '/api/1.1/xml'
        self.authtoken = ''

        #force urllib2 to not use a proxy
        proxy_handler = urllib2.ProxyHandler({})
        opener = urllib2.build_opener(proxy_handler)
        urllib2.install_opener(opener)
        self.login()

    #Gets called in __init__
    def login(self):
        """ logs you into the device """
        xml = etree.Element("LoginRequest")

        #if it has a token it adds it to the request 
        if(self.authtoken != ''):
            xml.set('session-id',self.authtoken)
            xml.set('sync-id', str(random.randint(1,65535)))

        #parses parameters from calls
        # for param,value in parameters.iteritems():
            # xml.set(param, str(value))
        xml.set('user-id', str(self.username))
        xml.set('password', str(self.password))
        
        #makes request and returns response
        data=etree.tostring(xml)
        request = urllib2.Request(self.url + self.api, data)
        request.add_header('Content-Type', 'text/xml')
        
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response = etree.XML(response.read())
   
        # response = request("Login", {'user-id' : self.username, 'password' : self.password})
        self.authtoken = response.attrib['session-id']
        return response

    # Contains a custom adhoc report request.
    def adhoc_report(self, query, site_ids=[], api_version='1.1.0',
            scan_ids=[], device_ids=[]):
        '''
        Execute an adhoc SQL query using the API. Additional parameters can
        be supplied to the function to apply filters to the request.
        '''
        response = self.ad_hoc_report_request("ReportAdhocGenerate", query,
            site_ids=site_ids, api_version=api_version,
            scan_ids=scan_ids, device_ids=device_ids)
        return response

    def asset_group_config(self, groupid):
        response = request(self, "AssetGroupConfig", {"group-id" : groupid})
        return etree.tostring(response)

    def asset_group_delete(self, groupid):
        response = request(self, "AssetGroupDelete", {"group-id" : groupid})
        return etree.tostring(response)

    def asset_group_listing(self):
        response = request(self, "AssetGroupListing")
        return etree.tostring(response)

    def asset_group_save(self, groupdtd):
        response = request(self, "AssetGroupSave", appendelements=[groupdtd])
        return etree.tostring(response)

    def device_delete(self, deviceid):
        response = request(self, "DeviceDelete", {"device-id" : deviceid})
        return etree.tostring(response)

    def download_report(self, reporturl):
        req = urllib2.Request(self.baseurl + reporturl)
        req.add_header('Cookie', 'nexposeCCSessionID=%s' % self.token)
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(req,context=gcontext)
        resxml = etree.XML(response.read())
        return resxml

    def engine_activity(self, engineid):
        response = request(self, "EngineActivity", {"engine-id" : engineid})
        activity = objectify.fromstring(etree.tostring(response))
        ss = activity.ScanSummary[0]
        vulns = []
        for vuln in ss.vulnerabilities:
            vulns.append(Vulnerability(**dict(vuln.items())))

        summaryItems = dict(ss.items())
        summaryItems['siteid'] = summaryItems['site-id']
        del summaryItems['site-id']
        summaryItems['scanid'] = summaryItems['scan-id']
        del summaryItems['scan-id']
        summaryItems['engineid'] = summaryItems['engine-id']
        del summaryItems['engine-id']
        summaryItems['tasks'] = Tasks(**dict(ss.tasks.items()))
        summaryItems['nodes'] = Nodes(**dict(ss.nodes.items()))
        summaryItems['vulns'] = vulns
        return ScanSummary(**summaryItems)

    def list_engines(self):
        response = request(self, "EngineListing")
        engines = objectify.fromstring(etree.tostring(response))
        enginesList = []
        engineSummaryList = []
        for engine in engines.EngineSummary:
            enginesList.append(dict(engine.items()))

        for engine in enginesList:
            engineSummaryList.append(EngineSummary(engine['id'], engine['name'], engine['address'], engine['port'], engine['status'], engine['scope']))

        return engineSummaryList

    def logout(self):
        response = request(self, "Logout")
        return response.attrib['success']

    def report_generate(self, reportid):
        response = request(self, "ReportGenerate", {'report-id' : reportid})
        return etree.tostring(response)

    def report_listing(self):
        response = request(self, "ReportListing")
        return etree.tostring(response)

    def report_template_listing(self):
        response = request(self, "ReportTemplateListing")
        return etree.tostring(response)

    def report_history(self, reportcfgid):
        response = request(self, "ReportHistory", {'reportcfg-id' : reportcfgid})
        return etree.tostring(response)

    def restart(self):
        response = request(self, "Restart")
        return etree.tostring(response)

    def scan_activity(self):
        response = request(self, "ScanActivity")
        scans = objectify.fromstring(etree.tostring(response))
        scanSummaryList = []
        for scan in scans.ScanSummary:
            vulns = []
            for vuln in scan.vulnerabilities:
                vulns.append(Vulnerability(**dict(vuln.items())))

            summaryItems = dict(scan.items())
            summaryItems['siteid'] = summaryItems['site-id']
            del summaryItems['site-id']
            summaryItems['scanid'] = summaryItems['scan-id']
            del summaryItems['scan-id']
            summaryItems['engineid'] = summaryItems['engine-id']
            del summaryItems['engine-id']
            summaryItems['tasks'] = Tasks(**dict(scan.tasks.items()))
            summaryItems['nodes'] = Nodes(**dict(scan.nodes.items()))
            summaryItems['vulns'] = vulns
            scanSummaryList.append(ScanSummary(**summaryItems))
            
        return scanSummaryList

    def scan_pause(self, scanid):
        response = request(self, "ScanPause", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_resume(self, scanid):
        response = request(self, "ScanResume", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_statistics(self, scanid):
        response = request(self, "ScanStatistics", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_status(self, scanid):
        response = request(self, "ScanStatus", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_stop(self, scanid):
        response = request(self, "ScanStop", {'scan-id' : scanid})
        return etree.tostring(response)

    def site_config(self, siteid):
        response = request(self, "SiteConfig", {"site-id" : siteid})
        return etree.tostring(response)

    def site_save(self, sitedtd):
        response = request(self, "SiteSave", appendelements=[sitedtd])
        return etree.tostring(response)

    def site_delete(self, siteid):
        response = request(self, "SiteDelete", {"site-id" : siteid})
        return etree.tostring(response)

    def site_device_listing(self, siteid):
        response = request(self, "SiteDeviceListing", {"site-id" : siteid})
        return etree.tostring(response)

    def site_device_scan(self, siteid, sitedtd):
        response = request(self, "SiteDevicesScan", {"site-id" : siteid}, \
            appendelements=sitedtd)
        return etree.tostring(response)

    def list_sites(self):
        response = request(self, "SiteListing")
        sites = objectify.fromstring(etree.tostring(response))
        sitesList = []
        siteSummaryList = []
        for site in sites.SiteSummary:
            sitesList.append(dict(site.items()))

        for site in sitesList:
            siteSummaryList.append(SiteSummary(site['description'], site['id'], site['name'], site['riskfactor'], site['riskscore']))

        return siteSummaryList

    def site_scan(self, siteid):
        response = request(self, "SiteScan", {"site-id" : siteid})
        return etree.tostring(response)

    def site_scan_history(self, siteid):
        response = request(self, "SiteScanHistory", {"site-id" : siteid})
        history = objectify.fromstring(etree.tostring(response))
        scans = []
        
        for scan in history.ScanSummary:
            vulns = []
            for vuln in scan.vulnerabilities:
                vulns.append(Vulnerability(**dict(vuln.items())))

            summaryItems = dict(scan.items())
            summaryItems['siteid'] = summaryItems['site-id']
            del summaryItems['site-id']
            summaryItems['scanid'] = summaryItems['scan-id']
            del summaryItems['scan-id']
            summaryItems['engineid'] = summaryItems['engine-id']
            del summaryItems['engine-id']
            summaryItems['tasks'] = Tasks(**dict(scan.tasks.items()))
            summaryItems['nodes'] = Nodes(**dict(scan.nodes.items()))
            summaryItems['vulns'] = vulns
            scans.append(ScanSummary(**summaryItems))
            
        return scans

    def system_update(self):
        response = request(self, "SystemUpdate")
        return etree.tostring(response)

    def system_information(self):
        response = request(self, "SystemInformation")
        return etree.tostring(response)

    def user_authenticator_listing(self):
        response = request(self, "UserAuthenticatorListing")
        return etree.tostring(response)

    def user_config(self, userid):
        response = request(self, "UserConfig", {"id" : userid})
        return User(*response[0].values())

    def user_delete(self, userid):
        response = request(self, "UserDelete", {"id" : userid})
        return etree.tostring(response)

    def user_listing(self):
        response = request(self, "UserListing")
        users = []
        for user in response:
            users.append(UserSummary(*user.values()))
            
        return users

    def vulnerability_details(self, vulnid):
        response = request(self, "VulnerabilityDetails", {"vuln-id" : vulnid})
        return etree.tostring(response)

    def vulnerability_listing(self):
        response = request(self, "VulnerabilityListing")
        return etree.tostring(response)

    # Adhoc Report Request Parser
    # By default API version 1.1.0 is used for the query, if you want to use
    # a newer API version (for example to get access to some SQL dimensions
    # and columns you can't see with 1.1.0, change api_version to something
    # newer (like 1.3.2)
    #
    # Additionally, site_ids and scan_ids can be passed into the function to
    # apply additional filters to the report request.
    def ad_hoc_report_request(self, call, query, site_ids=[],
        api_version='1.1.0', scan_ids=[], device_ids=[]):
        xml = etree.Element(call + "Request")

        # If an authentication token exists add it to the request.
        if (self.authtoken != ''):
            xml.set('session-id', self.authtoken)
            xml.set('sync-id', str(random.randint(1,65535)))

        # Create the configuration object.
        config = etree.Element('AdhocReportConfig')
        config.set('format', 'sql')

        # Create an object to potentially hold multiple filters.
        filters = etree.Element('Filters')

        # Add the required filters.
        filter_ver = etree.Element('filter')
        filter_ver.set('type', 'version')
        filter_ver.set('id', api_version)
        filter_query = etree.Element('filter')
        filter_query.set('type', 'query') 
        filter_query.set('id', query)

        # Append version and query filter to the object.
        filters.append(filter_ver)
        filters.append(filter_query)

        # If site filters were supplied, add those.
        for site in site_ids:
            filter_n = etree.Element('filter')
            filter_n.set('type', 'site')
            filter_n.set('id', str(site))
            filters.append(filter_n)
        
        # If scan filters were supplied, add those.
        for scan in scan_ids:
            filter_n = etree.Element('filter')
            filter_n.set('type', 'scan')
            filter_n.set('id', str(scan))
            filters.append(filter_n)

        # If device filters were supplied, add those.
        for device in device_ids:
            filter_n = etree.Element('filter')
            filter_n.set('type', 'device')
            filter_n.set('id', str(device))
            filters.append(filter_n)

        config.append(filters)

        xml.append(config)

        data=etree.tostring(xml)
        if print_query:
            print 'Making Query:\n', data, '\n'
        request = urllib2.Request(self.url + self.api, data)
        request.add_header('Content-Type', 'application/xml')
        
        # Make the request.
        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        response = urllib2.urlopen(request, context=gcontext)
        response_data = response.read()

        # We get the response back in base64 with a header. We need to
        # truncate the header and parse the base64 encoded data out. Just
        # omit the first 230 characters and the response remaining is csv.
        
        try: 
            # The 230 byte offset only strips the header on the response, also
            # strip the last line which is the MIME boundary.
            #
            # XXX This should be handled a lot better by properly parsing the
            # response returned by the server.
            response_data = '\r'.join(response_data.split('\r')[:-2])
            decoded_data = base64.b64decode(response_data[230:])
            return decoded_data
        except:
            # XXX We should probably raise an exception here so the
            # calling function can interpret the failure.
            print 'error parsing response - there might have been a ' + \
                'problem, see response from server below\n' + response_data
        return None
