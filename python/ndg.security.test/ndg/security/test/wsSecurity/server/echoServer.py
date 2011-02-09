#!/usr/bin/env python
#
# How to build an echo server using the extended code generation
#
import sys, os
from ConfigParser import SafeConfigParser

# Import the ZSI stuff you'd need no matter what
from ZSI.ServiceContainer import ServiceContainer

# This is a new method imported to show it's value
from ZSI.ServiceContainer import GetSOAPContext

from ndg.security.test.wsSecurity.server.EchoService_services_server import \
    EchoService as _EchoService

from ndg.security.common import wsSecurity

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_WSSESRV_UNITTEST_DIR'], file)


class EchoService(_EchoService):

    def __init__(self, **kw):
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        _EchoService.__init__(self, **kw)
        
    def sign(self, sw):
        '''\
        Overrides ServiceInterface class method to allow digital signature'''
        self.signatureHandler.sign(sw)
        
    def verify(self, ps):
        '''\
        Overrides ServiceInterface class method to allow signature 
        verification'''      
        self.signatureHandler.verify(ps)
        
    def soap_Echo(self, ps, **kw):
        '''Simple echo method to test WS-Security DSIG
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: response objects'''
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        response = _EchoService.soap_Echo(self, ps)    
        response.EchoResult = "Received message from client: " + \
                            self.request.EchoIn
        return response
    
    
    def authorize(self, auth_info, post, action):
        '''Override default simply in order to display client request info'''
        ctx = GetSOAPContext()
        print "-"*80
        print dir(ctx)
        print "Container: ", ctx.connection
        print "Parsed SOAP: ", ctx.parsedsoap
        print "Container: ", ctx.container
        print "HTTP Headers:\n", ctx.httpheaders
        print "-"*80
        print "Client Request:\n", ctx.xmldata
        return 1

   
if __name__ == "__main__":
    # Here we set up the server
        
    if 'NDGSEC_WSSESRV_UNITTEST_DIR' not in os.environ:
        os.environ['NDGSEC_WSSESRV_UNITTEST_DIR'] = \
            os.path.abspath(os.path.dirname(__file__))
    
    configFilePath = jnPath(os.environ['NDGSEC_WSSESRV_UNITTEST_DIR'],
                            "echoServer.cfg")
    cfg = SafeConfigParser()
    cfg.read(configFilePath)
    
    hostname = cfg.get('setUp', 'hostname')
    port = cfg.getint('setUp', 'port')
    path = cfg.get('setUp', 'path')
    
    wsseCfgFilePath = xpdVars(cfg.get('setUp', 'wsseCfgFilePath'))

    serviceContainer = ServiceContainer((hostname, port))   
    
    # Create the Inherited version of the server
    echo = EchoService()
    echo.signatureHandler = wsSecurity.SignatureHandler(cfg=wsseCfgFilePath)

    serviceContainer.setNode(echo, url=path)
    
    try:
        # Run the service container
        print "listening at http://%s:%s%s" % (hostname, port, path)
        serviceContainer.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
