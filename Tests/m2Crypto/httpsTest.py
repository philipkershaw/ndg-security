#!/use/bin/env python
from M2Crypto.httpslib import HTTPSConnection

hostname = 'gabriel.badc.rl.ac.uk'
#hostname = 'grid.bodc.nerc.ac.uk'
path = '/openid'
#
#body = '''<SOAP-ENV:Envelope 
#xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" 
#xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
#xmlns:ns1="urn:ndg.security.sessionMgr">
#<SOAP-ENV:Header></SOAP-ENV:Header>
#<SOAP-ENV:Body><ns1:getAttCert/></SOAP-ENV:Body>'''

#con = HTTPSConnection(hostname)
#con.putrequest('POST', path)
#con.putheader('Content-Type', 'text/xml')
#con.putheader('Content-Length', str(len(body)))
#con.endheaders()
#con.send(body)
#resp = con.getresponse()
#print resp.read()

con = HTTPSConnection(hostname)
con.putrequest('GET', path)
con.endheaders()
resp = con.getresponse()
print resp.read()
