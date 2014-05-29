#!/bin/python
import pnexpose

serveraddr = '172.16.138.130'
port = 3780
username = 'nxadmin'
password = 'nxpassword'
filters='version'
query = """SELECT fa.vulnerability_instances, fa.affected_assets, fa.most_recently_discovered, dv.title 
         FROM fact_vulnerability fa 
         JOIN dim_vulnerability dv USING (vulnerability_id) 
         where affected_assets > 0"""


#EXMAPLE 1
#prints report listings

#creates a nexposeClient object
nexposeClient = pnexpose.nexposeClient(serveraddr, port, username, password)

#EXAMPLE 1
#Print reports available 
response = n.report_listing()
print response

#EXAMPLE 2
#makes ad_hoc report queries using sql on specific sites
#call requires a query
query = """\
SELECT da.ip_address, da.host_name, dos.description AS operating_system, fad.last_discovered \
FROM dim_asset da \
JOIN dim_operating_system dos USING (operating_system_id) \
JOIN fact_asset_discovery fad USING (asset_id) \
"""

#call requires site ids in an array
sites = [1,2]

response = nexposeClient.adhoc_report(query,sites)
#response is a csv with the results
print response

