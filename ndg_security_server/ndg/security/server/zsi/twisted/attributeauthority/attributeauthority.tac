"""NDG Security Attribute Authority .tac file 

This file enables the Attribute Authority web service to be 
called under the Twisted framework

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/11/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import os, base64
from logging.config import fileConfig
try:
	_logConfig = os.path.join(os.environ["NDGSEC_DIR"],
							  'conf',
							  'attAuthorityLog.cfg')
	fileConfig(_logConfig)
except KeyError:
	from warnings import warn
	warn(\
	'"NDGSEC_DIR" environment variable must be set to enable logging config',
	RuntimeWarning)
	
import logging
log = logging.getLogger(__name__)

from ZSI.twisted.WSresource import WSResource
from twisted.application import service, internet
from twisted.web.server import Site
from twisted.web.resource import Resource

from \
ndg.security.server.zsi.twisted.attributeauthority.SessionManager_services_server\
 	import SessionManagerService

from ndg.security.server.attributeauthority import AttributeAuthority, \
	AttributeAuthorityAccessDenied
	
from ndg.security.common.wssecurity.dom import SignatureHandler
from ndg.security.server.zsi.twisted import WSSecurityHandlerChainFactory, \
	WSSecurityHandler

from ndg.security.common.X509 import X509Cert, X509CertRead


class AttributeAuthorityServiceSub(AttributeAuthorityService, WSResource):

    # Add WS-Security handlers
    factory = WSSecurityHandlerChainFactory

    def __init__(self):
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        WSResource.__init__(self)
         
        # Initialize Attribute Authority class - property file will be
        # picked up from default location under $NDG_DIR directory
        self.aa = AttributeAuthority()


    def soap_getAttCert(self, ps, **kw):
        '''Retrieve an Attribute Certificate
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = SessionManagerService.soap_getAttCert(self, ps)

        # Derive designated holder cert differently according to whether
        # a signed message is expected from the client - NB, this is dependent
        # on WS-Security properties having been set
        if srv.aa.has_key('WS-Security'):
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's proxy
            holderCert = WSSecurityHandler.signatureHandler.verifyingCert
        else:
            # No signature from client - they must instead provide the
            # designated holder cert via the userX509Cert input
            holderCert = request.UserX509Cert

        try:	
        	attCert = self.aa.getAttCert(userId=request.UserId,
                                         holderCert=holderCert,
                                         userAttCert=request.UserAttCert)  
	        response.AttCert = attCert.toString()
	        
        except AttributeAuthorityAccessDenied, e:
            response.Msg = str(e)
			
        return request, response
       

    def soap_getHostInfo(self, ps, **kw):
        '''Get information about this host
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = SessionManagerService.soap_getHostInfo(self, ps)
        
        response.Hostname = srv.aa.hostInfo.keys()[0]
        response.AaURI = srv.aa.hostInfo[response.Hostname]['aaURI']
        response.AaDN = srv.aa.hostInfo[response.Hostname]['aaDN']
        response.LoginURI = srv.aa.hostInfo[response.Hostname]['loginURI']
        response.LoginServerDN = \
        	srv.aa.hostInfo[response.Hostname]['loginServerDN']
        response.LoginRequestServerDN = \
        	srv.aa.hostInfo[response.Hostname]['loginRequestServerDN']

        return request, response
       

    def soap_getAllHostsInfo(self, ps, **kw):
        '''Get information about all hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = SessionManagerService.soap_getAllHostsInfo(self, ps)
        

        trustedHostInfo = srv.aa.getTrustedHostInfo()

		# Convert ready for serialization
		
		# First get info for THIS Attribute Authority ...
		# Nb. No role lsit applies here
        hosts = [response.new_hosts()]
        
        hosts[0].Hostname = srv.aa.hostInfo.keys()[0]
        
        hosts[0].AaURI = \
        	srv.aa.hostInfo[hosts[0].Hostname]['aaURI']
        hosts[0].AaDN = \
        	srv.aa.hostInfo[hosts[0].Hostname]['aaDN']

        hosts[0].LoginURI = srv.aa.hostInfo[hosts[0].Hostname]['loginURI']
        hosts[0].LoginServerDN = \
        	srv.aa.hostInfo[hosts[0].Hostname]['loginServerDN']
        hosts[0].LoginRequestServerDN = \
        	srv.aa.hostInfo[hosts[0].Hostname]['loginRequestServerDN']
        
		# ... then append info for other trusted attribute authorities...
        for hostname, hostInfo in trustedHostInfo.items():
            host = response.new_hosts()
			
            host.Hostname = hostname
            host.AaURI = hostInfo['aaURI']
            host.AaDN = hostInfo['aaDN']
            host.LoginURI = hostInfo['loginURI']
            host.LoginServerDN = hostInfo['loginServerDN']
            host.LoginRequestServerDN=hostInfo['loginRequestServerDN']
            host.RoleList = hostInfo['role']
			
            hosts.append(host)
			
        response.Hosts = hosts

        return request, response


    def soap_getTrustedHostInfo(self, ps, **kw):
        '''Get information about other trusted hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = \
                    	SessionManagerService.soap_getTrustedHostInfo(self, ps)
        
        trustedHostInfo = srv.aa.getTrustedHostInfo(role=request.Role)

		# Convert ready for serialization
        trustedHosts = []
        for hostname, hostInfo in trustedHostInfo.items():
            trustedHost = response.new_trustedHosts()
			
            trustedHost.Hostname = hostname
            trustedHost.AaURI = hostInfo['aaURI']
            trustedHost.AaDN = hostInfo['aaDN']
            trustedHost.LoginURI = hostInfo['loginURI']
            trustedHost.LoginServerDN = hostInfo['loginServerDN']
            trustedHost.LoginRequestServerDN=hostInfo['loginRequestServerDN']
            trustedHost.RoleList = hostInfo['role']
			
            trustedHosts.append(trustedHost)
			
        response.TrustedHosts = trustedHosts
		
        return request, response


    def soap_getX509Cert(self, ps, **kw):
    	'''Retrieve Attribute Authority's X.509 certificate
    	
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = AttributeAuthorityService.soap_getX509Cert(self, ps)
        
        x509Cert = X509CertRead(srv.aa['signingCertFilePath'])
        response.X509Cert = base64.encodestring(x509Cert.asDER())
        return request, response


root = Resource()

# Create Service
srv = AttributeAuthorityServiceSub()
if srv.aa.has_key('WS-Security'):
    # Initialise WS-Security signature handler passing Attribute Authority
    # public and private keys
    
    # Inclusive namespaces for Exclusive C14N
    refC14nInclNS = srv.aa['refC14nInclNS']
    signedInfoC14nInclNS = srv.aa['signedInfoC14nInclNS']
    
    WSSecurityHandler.signatureHandler = SignatureHandler(\
			                verifyingCertFilePath=srv.aa['verifyingCertFilePath'],
			                signingCertFilePath=srv.aa['signingCertFilePath'],
			                signingPriKeyFilePath=srv.aa['signingPriKeyFilePath'],
			                signingPriKeyPwd=srv.aa['signingPriKeyPwd'],
			                caCertFilePathList=srv.aa.get('caCertFilePathList'),
			                refC14nInclNS=refC14nInclNS,
			                signedInfoC14nInclNS=signedInfoC14nInclNS,
			                reqBinSecTokValType=srv.aa.get('reqBinSecTokValType'),
			                applySignatureConfirmation=srv.aa.get('applySignatureConfirmation'))

# Add Service to Attribute Authority branch
root.putChild('AttributeAuthority', srv)
siteFactory = Site(root)
if srv.aa['useSSL']:
	log.info("Running over https ...")

	os.putenv("OPENSSL_ALLOW_PROXY_CERTS", "1")

	import twisted.protocols.policies as policies

	# Using M2Crypto
 	from M2Crypto import SSL
 	from M2Crypto.SSL import TwistedProtocolWrapper
 	from M2Crypto.SSL.TwistedProtocolWrapper import TLSProtocolWrapper

	siteFactory.startTLS = True
	siteFactory.sslChecker = SSL.Checker.Checker()
	
	# TODO: Python ssl client seems to require SSL vers 2 is this a security
	# risk?
	ctx = SSL.Context(protocol='sslv23')
	ctx.set_cipher_list("NULL-MD5:ALL:!ADH:!EXP:@STRENGTH")
	ctx.load_cert(srv.aa['sslCertFile'], 
				  srv.aa['sslKeyFile'],
				  callback=lambda *args, **kw: srv.aa['sslKeyPwd'])
				  
	ctx.set_allow_unknown_ca(False)
	
	# TODO: resolve check - verify_peer setting fails with
	# BIOError: 'no certificate returned' error 18
	#    ctx.set_verify(SSL.verify_peer, 10)
	ctx.set_verify(SSL.verify_client_once, 1)
	
	ctx.load_verify_locations(capath=srv.aa['sslCACertDir'])
	
	class ContextFactory:
	    def getContext(self):
	        return ctx
	
	factory = policies.WrappingFactory(siteFactory)
	factory.protocol.TLS = True
	factory.protocol = lambda factory, wrappedProtocol: \
	    TLSProtocolWrapper(factory,
	                       wrappedProtocol,
	                       startPassThrough=0,
	                       client=0,
	                       contextFactory=ContextFactory(),
	                       postConnectionCheck=None)
	
	siteFactory = factory
	
	port = internet.TCPServer(srv.aa['portNum'], siteFactory)
	port.CERTFILE = srv.aa['sslCertFile']
	port.KEYFILE = srv.aa['sslKeyFile']
	root.__class__.server = port
else:	
	# Non-SSL
	log.info("Running over http ...")	
	port = internet.TCPServer(srv.aa['portNum'], siteFactory)

application = service.Application("AttributeAuthorityContainer")
port.setServiceParent(application)
	
