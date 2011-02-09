#!/usr/bin/env python
"""NDG Security Session Manager .tac file 

This file enables the Session Manager web service to be 
called under the Twisted framework

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/11/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

import os, base64

from logging.config import fileConfig
try:
	_logConfig = os.path.join(os.environ["NDGSEC_DIR"],
							  'conf',
							  'sessionMgrLog.cfg')
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

from ndg.security.server.SessionMgr.SessionMgr_services_server import \
	SessionMgrService as _SessionMgrService
from ndg.security.server.SessionMgr import SessionMgr
from ndg.security.common.wsSecurity import SignatureHandler
from ndg.security.server.twisted import WSSecurityHandler, \
	WSSecurityHandlerChainFactory
	

from ndg.security.common.X509 import X509CertRead


class SessionMgrService(_SessionMgrService, WSResource):

    # Add WS-Security handlers
    factory = WSSecurityHandlerChainFactory
        
    def __init__(self):
        '''Initialize Session Manager class - encapsulates inner workings 
        including session management and proxy delegation
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
        	import pdb
        	pdb.set_trace()

        WSResource.__init__(self) 
        self.sm = SessionMgr()


    def soap_connect(self, ps, **kw):
        '''Connect to Session Manager and create a user session
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''

        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _SessionMgrService.soap_connect(self, ps)
        
        result = self.sm.connect(username=request.Username,
								 passphrase=request.Passphrase,
								 createServerSess=request.CreateServerSess)
					
        response.UserCert, response.UserPriKey, response.issuingCert, \
        	response.SessID = result
		         
        return request, response


    def soap_disconnect(self, ps, **kw):
        '''Disconnect and remove user's session
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	            
        request, response = _SessionMgrService.soap_disconnect(self, ps)
        
        # Derive designated user ID differently according to whether
        # a session ID was passed and the message was signed
        sessID = request.SessID or None
        	
        if srv.sm['useSignatureHandler']:
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's proxy
            userCert = WSSecurityHandler.signatureHandler.verifyingCert
        else:
            userCert = request.UserCert

        self.sm.deleteUserSession(sessID=sessID, userCert=userCert)
        return request, response


    def soap_getSessionStatus(self, ps, **kw):
        '''Check for existence of a session with given session ID or user
        Distinguished Name
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''

        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _SessionMgrService.soap_getSessionStatus(self, ps)
        
        response.IsAlive = self.sm.getSessionStatus(userDN=request.UserDN,
								 		            sessID=request.SessID)
		         
        return request, response


    def soap_getAttCert(self, ps, **kw):
        '''Get Attribute Certificate from a given Attribute Authority
        and cache it in user's Credential Wallet
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _SessionMgrService.soap_getAttCert(self, ps)

        # Get certificate corresponding to private key that signed the
        # message - i.e. the user's        	
        if srv.sm['useSignatureHandler']:
            # Get certificate corresponding to private key that signed the
            # message - i.e. the user's proxy
            userCert = WSSecurityHandler.signatureHandler.verifyingCert
        else:
            userCert = None
        
		# Cert used in signature is prefered over userCert input element - 
		# userCert may have been omitted.
        result = self.sm.getAttCert(\
			        	    userCert=userCert or request.UserCert,
					        sessID=request.SessID,
					        aaURI=request.AttAuthorityURI,
					        reqRole=request.ReqRole,
					        mapFromTrustedHosts=request.MapFromTrustedHosts,
					        rtnExtAttCertList=request.RtnExtAttCertList,
					        extAttCertList=request.ExtAttCert,
					        extTrustedHostList=request.ExtTrustedHost)


        if result[0]:
        	response.AttCert = result[0].toString() 
        	
        response.Msg, response.ExtAttCertOut = result[1:]
        
        return request, response


    def soap_getX509Cert(self, ps, **kw):
        '''Return Session Manager's X.509 certificate
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: request and response objects'''        
        if self.__debug:
        	import pdb
        	pdb.set_trace()
        	
        request, response = _SessionMgrService.soap_getX509Cert(self, ps)

        x509Cert = X509CertRead(srv.sm['certFile'])
        response.X509Cert = base64.encodestring(x509Cert.asDER())
        return request, response


# Create Service
srv = SessionMgrService()

if srv.sm['useSignatureHandler']:
	# Initialise WS-Security signature handler passing Session Manager
	# public and private keys
    
    # Inclusive namespaces for Exclusive C14N
	refC14nKw = {'unsuppressedPrefixes': srv.sm['wssRefInclNS']}
	signedInfoC14nKw = {'unsuppressedPrefixes':
					    srv.sm['wssSignedInfoInclNS']}

	WSSecurityHandler.signatureHandler = SignatureHandler(\
							verifyingCertFilePath=srv.sm['clntCertFile'],
                            signingCertFilePath=srv.sm['certFile'],
                            signingPriKeyFilePath=srv.sm['keyFile'],
                            signingPriKeyPwd=srv.sm['keyPwd'],
                            caCertFilePathList=srv.sm.get('caCertFileList'),
			                refC14nKw=refC14nKw,
			                signedInfoC14nKw=signedInfoC14nKw)

# Add Service to Session Manager branch
root = Resource()
root.putChild('SessionManager', srv)
siteFactory = Site(root)

if srv.sm['useSSL']:
	# Use SSL connection
	log.info("Running over https ...")	

	# Using M2Crypto ...
	import os
	os.putenv("OPENSSL_ALLOW_PROXY_CERTS", "1")

	import twisted.protocols.policies as policies
	from M2Crypto import SSL
	from M2Crypto.SSL import TwistedProtocolWrapper
	from M2Crypto.SSL.TwistedProtocolWrapper import TLSProtocolWrapper
	
	siteFactory.startTLS = True
	siteFactory.sslChecker = SSL.Checker.Checker()

	# TODO: Python ssl client seems to require SSL vers 2 is this a security
	# risk?
	ctx = SSL.Context(protocol='sslv23')
	ctx.set_cipher_list("NULL-MD5:ALL:!ADH:!EXP:@STRENGTH")
	ctx.load_cert(srv.sm['sslCertFile'], 
    			  srv.sm['sslKeyFile'],
    			  callback=lambda *args, **kw: srv.sm['sslKeyPwd'])
    			  
	ctx.set_allow_unknown_ca(False)

    # TODO: resolve check - verify_peer setting fails with
    # BIOError: 'no certificate returned' error 18
#    ctx.set_verify(SSL.verify_peer, 10)
	ctx.set_verify(SSL.verify_client_once, 1)

	ctx.load_verify_locations(capath=srv.sm['sslCACertDir'])

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
	
	port = internet.TCPServer(srv.sm['portNum'], siteFactory)
	port.CERTFILE = srv.sm['sslCertFile']
	port.KEYFILE = srv.sm['sslKeyFile']
	root.__class__.server = port
else:	
	# Non-SSL
	log.info("Running over http ...")
	port = internet.TCPServer(srv.sm['portNum'], siteFactory)

application = service.Application("SessionManagerContainer")
port.setServiceParent(application)
