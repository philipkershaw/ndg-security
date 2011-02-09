#!/usr/bin/env python
"""NDG Security Certificate Authority .tac file 

This file enables the Session Manager web service to be 
called under the Twisted framework

NERC Data Grid Project

@author P J Kershaw 23/11/06

@copyright (C) 2007 CCLRC & NERC

@license This software may be distributed under the terms of the Q Public 
License, version 1.0 or later.
"""
import sys

from ZSI.twisted.WSresource import WSResource
from twisted.application import service, internet
from twisted.web.server import Site
from twisted.web.resource import Resource

from ndg.security.server.ca.CertificateAuthority_services_server import \
	CertificateAuthorityService
from ndg.security.server.ca import SimpleCA, SimpleCAPassPhraseError
from ndg.security.common.wsSecurity import SignatureHandler
from ndg.security.server.twisted import WSSecurityHandlerChainFactory, \
	WSSecurityHandler


class CertificateAuthorityServiceSub(CertificateAuthorityService, WSResource):

    # Add WS-Security handlers
    factory = WSSecurityHandlerChainFactory
        
    def __init__(self):
        WSResource.__init__(self)
         
        # Initialize SimpleCA class 
        self.ca = SimpleCA()
        
        
        # Check for CA pass-phrase input
        try:
        	self.ca.chkCAPassphrase()
        except SimpleCAPassPhraseError:
	        import getpass

	        nTries = 0
	        while nTries < 10:
	            try:
	                self.ca.caPassphrase = \
	                    getpass.getpass(prompt="CA Pass-phrase: ")
	                break
	            
	            except KeyboardInterrupt:
	                sys.exit(1)
	                
	            except SimpleCAPassPhraseError:
	                nTries += 1
	                if nTries >= 10:
	                    print >>sys.stderr, \
	                        "Invalid Pass-phrase - exiting after 10 attempts"
	                    sys.exit(1)
	                else:
	                    print >>sys.stderr, "Invalid pass-phrase"

       
    def soap_issueCert(self, ps, **kw):
        import pdb;pdb.set_trace()
        request,response = CertificateAuthorityService.soap_issueCert(self,ps)
        
        response.X509Cert = self.ca.sign(certReq=request.X509CertReq)[0]
        return request, response

    def soap_revokeCert(self, ps, **kw):
        #import pdb;pdb.set_trace()
        request,response=CertificateAuthorityService.soap_revokeCert(self,ps)

        self.ca.revokeCert(cert=request.Cert)
		         
        return request, response

    def soap_getCRL(self, ps, **kw):
        #import pdb;pdb.set_trace()
        request, response = CertificateAuthorityService.soap_getCRL(self, ps)
        
        response.Crl = self.ca.genCRL()
        return request, response


# Create Service
srv = CertificateAuthorityServiceSub()

# Initialise WS-Security signature handler passing Certificate Authority
# public and private keys
WSSecurityHandler.signatureHandler = SignatureHandler(\
							verifyingCertFilePath=srv.ca.get('clntCertFile'),
                            signingCertFilePath=srv.ca['certFile'],
                            signingPriKeyFilePath=srv.ca['keyFile'],
                            signingPriKeyPwd=srv.ca['keyPwd'])

# Add Service to Session Manager branch
root = Resource()
root.putChild('CertificateAuthority', srv)
siteFactory = Site(root)

if srv.ca['useSSL']:
	# Use SSL connection
	from twisted.internet import ssl
	
	# Nb. ssl.DefaultOpenSSLContextFactory requires pyOpenSSL
	ctxFactory = ssl.DefaultOpenSSLContextFactory(srv.ca['sslKeyFile'], 
												  srv.ca['sslCertFile'])
	port = internet.SSLServer(srv.ca['portNum'], siteFactory, ctxFactory)
else:	
	# Non-SSL
	port = internet.TCPServer(srv.ca['portNum'], siteFactory)

application = service.Application("CertificateAuthorityContainer")
port.setServiceParent(application)
