# example.tac
from AttAuthority_services_server import AttAuthorityService
from ZSI.twisted.WSresource import WSResource
from twisted.application import service, internet
from twisted.web.server import Site
from twisted.web.resource import Resource
import socket

class AttAuthorityImpl(AttAuthorityService, WSResource):
     def __init__(self):
         WSResource.__init__(self)

     def soap_getAttCert(self, ps, **kw):
         print 'soap_getAttCert'
         #import pdb;pdb.set_trace()
         request, response = AttAuthorityService.soap_getAttCert(self, ps)
         response._attCert = 'ATTRIBUTE CERT'
         return request, response

portNum = 5700
hostname = socket.gethostname()

root = Resource()
root.putChild('AttributeAuthority',  AttAuthorityImpl())
siteFactory = Site(root)
application = service.Application("WSRF-Container")
port = internet.TCPServer(portNum, siteFactory)#, interface=hostname)
port.setServiceParent(application)