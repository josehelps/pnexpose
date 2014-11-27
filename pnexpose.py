#!/bin/python

import urllib2
from lxml import etree
import random
import base64

#Dump Object Function
def dump(obj):
  for attr in dir(obj):
      print "obj.%s = %s" % (attr, getattr(obj, attr))


# Creates class for the client
class nexposeClient():
    def __init__(self, server, port, username, password):
        """ nexposeClient Class init call """
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
        response = self.request("Login", {'user-id' : self.username, 'password' : self.password})
        self.authtoken = response.attrib['session-id']

    #Contains custom request
    def adhoc_report(self,query,site_ids):
        """Takes in a query object in the for of SQL and an array with site ids"""
        response = self.ad_hoc_report_request("ReportAdhocGenerate",query,site_ids)
        return response

    def asset_group_config(self, groupid):
        response = self.request("AssetGroupConfig", {"group-id" : groupid})
        return etree.tostring(response)

    def asset_group_delete(self, groupid):
        response = self.request("AssetGroupDelete", {"group-id" : groupid})
        return etree.tostring(response)

    def asset_group_listing(self):
        response = self.request("AssetGroupListing")
        return etree.tostring(response)

    def asset_group_save(self, groupid):
        response = self.request("AssetGroupSave", {"group-id" : groupid})
        return etree.tostring(response)

    def device_delete(self, deviceid):
        response = self.request("DeviceDelete", {"device-id" : deviceid})
        return etree.tostring(response)

    def download_report(self, reporturl):
        req = urllib2.Request(self.baseurl + reporturl)
        req.add_header('Cookie', 'nexposeCCSessionID=%s' % self.token)
        response = urllib2.urlopen(req)
        resxml = etree.XML(response.read())
        return resxml

    def engine_activity(self, engineid):
        response = self.request("EngineActivity", {"engine-id" : engineid})
        return etree.tostring(response)

    def engine_listing(self):
        response = self.request("EngineListing")
        return etree.tostring(response)

    def logout(self):
        response = self.request("Logout")
        return response.attrib['success']

    def report_generate(self, reportid):
        response = self.request("ReportGenerate", {'report-id' : reportid})
        return etree.tostring(response)

    def report_listing(self):
        response = self.request("ReportListing")
        return etree.tostring(response)

    def report_template_listing(self):
        response = self.request("ReportTemplateListing")
        return etree.tostring(response)

    def report_history(self, reportcfgid):
        response = self.request("ReportHistory", {'reportcfg-id' : reportcfgid})
        return etree.tostring(response)

    def restart(self):
        response = self.request("Restart")
        return etree.tostring(response)

    def scan_activity(self):
        response = self.request("ScanActivity")
        return etree.tostring(response)

    def scan_pause(self, scanid):
        response = self.request("ScanPause", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_resume(self, scanid):
        response = self.request("ScanResume", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_statistics(self, scanid):
        response = self.request("ScanStatistics", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_status(self, scanid):
        response = self.request("ScanStatus", {'scan-id' : scanid})
        return etree.tostring(response)

    def scan_stop(self, scanid):
        response = self.request("ScanStop", {'scan-id' : scanid})
        return etree.tostring(response)

    def site_config(self, siteid):
        response = self.request("SiteConfig", {"site-id" : siteid})
        return etree.tostring(response)

    def site_save(self, sitedtd):
        response = self.request("SiteSave", appendelements=sitedtd)
        return etree.tostring(response)

    def site_delete(self, siteid):
        response = self.request("SiteDelete", {"site-id" : siteid})
        return etree.tostring(response)

    def site_device_listing(self, siteid):
        response = self.request("SiteDeviceListing", {"site-id" : siteid})
        return etree.tostring(response)

    def site_listing(self):
        response = self.request("SiteListing")
        return etree.tostring(response)

    def site_scan(self, siteid):
        response = self.request("SiteScan", {"site-id" : siteid})
        return etree.tostring(response)

    def site_scan_history(self, siteid):
        response = self.request("SiteScanHistory", {"site-id" : siteid})
        return etree.tostring(response)

    def system_update(self):
        response = self.request("SystemUpdate")
        return etree.tostring(response)

    def system_information(self):
        response = self.request("SystemInformation")
        return etree.tostring(response)

    def user_authenticator_listing(self):
        response = self.request("UserAuthenticatorListing")
        return etree.tostring(response)

    def user_config(self, userid):
        response = self.request("UserConfig", {"id" : userid})
        return etree.tostring(response)

    def user_delete(self, userid):
        response = self.request("UserDelete", {"id" : userid})
        return etree.tostring(response)

    def user_listing(self):
        response = self.request("UserListing")
        return etree.tostring(response)

    def vulnerability_details(self, vulnid):
        response = self.request("VulnerabilityDetails", {"vuln-id" : vulnid})
        return etree.tostring(response)

    def vulnerability_listing(self):
        response = self.request("VulnerabilityListing")
        return etree.tostring(response)



    #Request parser
    def request(self, call, parameters={}, appendelements=[]):
        """ Processes a Request for an API call """
        xml = etree.Element(call + "Request")

        #if it has a token it adds it to the request 
        if(self.authtoken != ''):
            xml.set('session-id',self.authtoken)
            xml.set('sync-id', str(random.randint(1,65535)))

        #parses parameters from calls
        for param,value in parameters.iteritems():
            xml.set(param, str(value))
        
        for el in appendelements:
            xml.append(etree.fromstring(el))

        #makes request and returns response
        data=etree.tostring(xml)
        request = urllib2.Request(self.url + self.api, data)
        request.add_header('Content-Type', 'text/xml')
        
        response = urllib2.urlopen(request)
        response = etree.XML(response.read())
        return response
    
    #adhoc report request parser
    def ad_hoc_report_request(self, call, query, site_id=[]):
        """ Processes a Request for an API call """
        #Could be integrated into regular request, although it could complicate that function
        xml = etree.Element(call + "Request")

        #if it has a token it adds it to the request 
        if(self.authtoken != ''):
            xml.set('session-id',self.authtoken)
            xml.set('sync-id', str(random.randint(1,65535)))

        #create configuration object
        config = etree.Element('AdhocReportConfig')
        config.set('format', 'sql')

        #create object to store multiple filters 
        filters = etree.Element("Filters")

        #create filters
        filter_ver = etree.Element("filter")
        filter_ver.set('type','version')
        filter_ver.set('id','1.1.0')

        filter_query = etree.Element("filter")
        filter_query.set('type','query') 
        filter_query.set('id', query)

        #append version and query filter to the query object
        filters.append(filter_ver)
        filters.append(filter_query)

        #add sites as filters as well
        for site in site_id:
            filter_n =''
            filter_n = site
            filter_n = etree.Element("filter")
            filter_n.set('type','site')
            filter_n.set('id',str(site))

            #append it to the query object
            filters.append(filter_n)
        
        #put the queries as part of the config object
        config.append(filters)
        #place the config inside the request object
        xml.append(config)

        #flatten the xml object
        data=etree.tostring(xml)
        print "Making Query:\n", data, "\n"
        request = urllib2.Request(self.url + self.api, data)
        request.add_header('Content-Type', 'application/xml')
        
        #make request
        response = urllib2.urlopen(request)
        response_data = response.read()

        #because the response comes back in base64 and with a header
        #we need to truncate the header and parse the base64
        #remove the first 230 characters - header
        #the response should be a csv output
        
        error = 'error parsing response, there might have been a problem see response\n' + response_data
        try: 
            decoded_data = base64.b64decode(response_data[230:])
            return decoded_data
        except:
            print 'error parsing response - there might have been a problem, see response from server below\n' + response_data
        



