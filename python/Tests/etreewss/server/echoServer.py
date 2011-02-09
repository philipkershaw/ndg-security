#!/usr/bin/env python
#
# How to build an echo server using the extended code generation
#
import sys, os
from ConfigParser import SafeConfigParser

# Import the ZSI stuff you'd need no matter what
from ZSI.ServiceContainer import ServiceContainer, SOAPRequestHandler, \
                                SOAPContext, _contexts, SimpleWSResource, \
                                ServiceInterface

# This is a new method imported to show it's value
from ZSI.ServiceContainer import GetSOAPContext

from ndg.security.test.wsSecurity.server.EchoService_services_server import \
    EchoService as _EchoService

from ndg.security.common.wssecurity.etree import SignatureHandler
from ndg.security.common.zsi.elementtreeproxy import ElementTreeProxy

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_WSSESRV_UNITTEST_DIR'], file)


import thread
from ZSI.address import Address
from ZSI.parse import ParsedSoap
from ZSI.writer import SoapWriter
from ZSI import ParseException, FaultFromException, FaultFromZSIException, \
                Fault
                
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

class ElementTreeSOAPRequestHandler(SOAPRequestHandler):
    '''Override SOAPRequestHandler to enable use of ElementTree for parser
    and writer'''
    
    def do_POST(self):
        '''The POST command.
        action -- SOAPAction(HTTP header) or wsa:Action(SOAP:Header)
        '''
        soapAction = self.headers.getheader('SOAPAction')
        post = self.path
        if not post:
            raise PostNotSpecified, 'HTTP POST not specified in request'
        if soapAction:
            soapAction = soapAction.strip('\'"')
        post = post.strip('\'"')
        try:
            ct = self.headers['content-type']
            if ct.startswith('multipart/'):
                cid = resolvers.MIMEResolver(ct, self.rfile)
                xml = cid.GetSOAPPart()
                ps = ParsedSoap(xml, 
                                resolver=cid.Resolve,
                                readerclass=ElementTreeProxy)
            elif self.headers.get('transfer-encoding') == 'chunked':
                # read content length from first line
                hexLength = self.rfile.readline()
                length = int(hexLength, 16)
                xml = self.rfile.read(length)
                ps = ParsedSoap(xml, readerclass=ElementTreeProxy)
            else:
                length = int(self.headers['content-length'])
                xml = self.rfile.read(length)
                ps = ParsedSoap(xml, readerclass=ElementTreeProxy)
        except ParseException, e:
            self.send_fault(FaultFromZSIException(e))
        except Exception, e:
            # Faulted while processing; assume it's in the header.
            self.send_fault(FaultFromException(e, 1, sys.exc_info()[2]))
        else:
            # Keep track of calls
            thread_id = thread.get_ident()
            _contexts[thread_id] = SOAPContext(self.server, xml, ps,
                                               self.connection,
                                               self.headers, soapAction)

            try:
                _Dispatch(ps, self.server, self.send_xml, self.send_fault, 
                    post=post, action=soapAction)
            except Exception, e:
                self.send_fault(FaultFromException(e, 0, sys.exc_info()[2]))

            # Clean up after the call
            if _contexts.has_key(thread_id):
                del _contexts[thread_id]

def _Dispatch(ps, server, SendResponse, SendFault, post, action, nsdict={}, 
              **kw):
    '''Redefine ZSI.Container._Dispatch to enable use of ElementTree for 
    SoapWriter
    '''
    localURL = 'http://%s:%d%s' %(server.server_name,server.server_port,post)
    address = action
    service = server.getNode(post)
    isWSResource = False
    if isinstance(service, SimpleWSResource):
        isWSResource = True
        service.setServiceURL(localURL)
        address = Address()
        try:
            address.parse(ps)
        except Exception, e:
            return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)
        if action and action != address.getAction():
            e = WSActionException('SOAP Action("%s") must match WS-Action("%s") if specified.' \
                %(action,address.getAction()))
            return SendFault(FaultFromException(e, 0, None), **kw)
        action = address.getAction()

    if isinstance(service, ServiceInterface) is False:
        e = NoSuchService('no service at POST(%s) in container: %s' %(post,server))
        return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)

    if not service.authorize(None, post, action):
        return SendFault(Fault(Fault.Server, "Not authorized"), code=401)
        #try:
        #    raise NotAuthorized()
        #except Exception, e:
            #return SendFault(FaultFromException(e, 0, None), code=401, **kw)
            ##return SendFault(FaultFromException(NotAuthorized(), 0, None), code=401, **kw)

    try:
        method = service.getOperation(ps, address)
    except Exception, e:
        return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)

    try:
        if isWSResource is True: 
            result = method(ps, address)
        else: 
            result = method(ps)
    except Exception, e:
        return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)

    # Verify if Signed
    service.verify(ps)

    # If No response just return.
    if result is None:
        return

    sw = SoapWriter(nsdict=nsdict, outputclass=ElementTreeProxy)
    try:
        sw.serialize(result)
    except Exception, e:
        return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)

    if isWSResource is True:
        action = service.getResponseAction(action)
        addressRsp = Address(action=action)
        try:
            addressRsp.setResponseFromWSAddress(address, localURL)
            addressRsp.serialize(sw)
        except Exception, e:
            return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)

    # Create Signatures
    service.sign(sw)

    try:
        soapdata = str(sw)
        return SendResponse(soapdata, **kw)
    except Exception, e:
        return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)


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
    echo.signatureHandler = SignatureHandler(cfgFilePath=wsseCfgFilePath)

    serviceContainer.setNode(echo, url=path)
    serviceContainer.RequestHandlerClass = ElementTreeSOAPRequestHandler
    
    try:
        # Run the service container
        print "listening at http://%s:%s%s" % (hostname, port, path)
        serviceContainer.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
