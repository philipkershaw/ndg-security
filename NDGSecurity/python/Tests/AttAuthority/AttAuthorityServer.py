#!/usr/bin/env python
#
# How to build an AttributeAuthority server using the extended code generation
#
import sys

# Import the ZSI stuff you'd need no matter what
from ZSI.ServiceContainer import ServiceContainer, SOAPRequestHandler

# This is a new method imported to show it's value
from ZSI.ServiceContainer import GetSOAPContext

# Import the generated Server Object
from ndg.security.common.zsi.attributeauthority.AttributeAuthority_services_server import AttributeAuthorityService

    
# Create a Server implementation

#_____________________________________________________________________________
class AttributeAuthoritySOAPRequestHandler(SOAPRequestHandler):
     """Add a do_GET method to return the WSDL on HTTP GET requests.
     Please note that the path to the wsdl file is derived from what
     the HTTP invocation delivers (which is put into the self.path
     attribute), so you might want to change this addressing scheme.
     """
     def do_GET(self):
         """Return the WSDL file."""         
         self.send_xml(AttributeAuthorityService._wsdl)
         
     def do_POST(self):
          """Fudge to get _Dispatch to pick up the correct address
          - seems to be necessary when putting proxy redirect for port in
          the wsdl e.g. http://glue.badc.rl.ac.uk/sessionMgr points to the
          default port for the Session Manager."""
          self.path = "/AttributeAuthorityServIn"
          SOAPRequestHandler.do_POST(self)
   
class AttributeAuthorityImpl(AttributeAuthorityService):

     def soap_getAttCert(self, ps, **kw):
         #import pdb;pdb.set_trace()
         response = AttributeAuthorityService.soap_getAttCert(self, ps)
         response.set_element_attCert('ATTRIBUTE CERT')
         return response
     
# Here we set up the server
serviceContainer = ServiceContainer(('localhost', 5700),
                RequestHandlerClass=AttributeAuthoritySOAPRequestHandler)


# Create the Inherited version of the server
import sys
service = AttributeAuthorityImpl()
serviceContainer.setNode(service, url="/AttributeAuthorityServIn")

try:
    # Run the service container
    serviceContainer.serve_forever()
except KeyboardInterrupt:
    sys.exit(0)