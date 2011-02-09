"""NDG Attribute Authority Web service server side interface.  Generated and 
adapted from:

wsdl2dispatch -f attAuthority.wsdl

NERC Data Grid Project

P J Kershaw 19/01/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

from attAuthority_services import *
from ZSI.ServiceContainer import ServiceSOAPBinding

from AttAuthority import *

# Create custom XML formatted error response where needed
from AttAuthorityIO import *


class attAuthority(ServiceSOAPBinding):
    soapAction = {
        'urn:attAuthority#getTrustedHostInfo': 'soap_getTrustedHostInfo',
        'urn:attAuthority#reqAuthorisation': 'soap_reqAuthorisation',
        'urn:attAuthority#getPubKey': 'soap_getPubKey',
        }

    def __init__(self, srv, debug=False, post='/attAuthority.wsdl', **kw):
        
        ServiceSOAPBinding.__init__(self, post)

        # Link WS to underlying attribute authority class instance
        if not isinstance(srv, AttAuthority):
            AttAuthorityError("Expecting AttAuthority type")
            
        self.__srv = srv
        
        self.__debug = debug
        

    #_________________________________________________________________________
    def soap_getTrustedHostInfo(self, ps):
       
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        # input vals in request object
        reqArgs = ps.Parse(trustedHostInfoRequestWrapper)
        reqTxt = str(reqArgs._trustedHostInfoReq)
        
        # assign return values to response object
        resp = trustedHostInfoResponseWrapper()
        
        
        try:
            # Decrypt and parse input
            reqKeys = TrustedHostInfoReq(xmlTxt=reqTxt,
                                     encrPriKeyFilePath=self.__srv['keyFile'],
                                     encrPriKeyPwd=self.__srv['keyPwd'])
                   
            trustedHosts = self.__srv.getTrustedHostInfo(**reqKeys.xmlTags)
            trustedHostInfoResp = TrustedHostInfoResp(\
                                                   trustedHosts=trustedHosts)                                         
        except Exception, e:
            trustedHostInfoResp = TrustedHostInfoResp(errMsg=str(e))
            
            
        try:
            # Encrypt response and convert into XML formatted string
            if 'encrCert' in reqKeys:
                
                # ConnectResp class expects the public key to be in a file
                # - Copy public key string content into a temporary file
                encrCertTmpFile = tempfile.NamedTemporaryFile()                    
                open(encrCertTmpFile.name, "w").write(reqKeys['encrCert'])
    
                trustedHostInfoResp.encrypt(\
                                    encrPubKeyFilePath=encrCertTmpFile.name)
                
        except Exception, e:
            trustedHostInfoResp = TrustedHostInfoResp(\
                                  statCode=TrustedHostInfoResp.accessError,
                                  errMsg=str(e))

        
        # Convert response into encrypted XML formatted string    
        resp._trustedHostInfoResp = trustedHostInfoResp()
        return resp


    #_________________________________________________________________________
    def soap_reqAuthorisation(self, ps):

        if self.__debug:
            import pdb
            pdb.set_trace()
        
        # input vals in request object
        reqArgs = ps.Parse(authorisationRequestWrapper)
        reqTxt = str(reqArgs._authorisationReq)

        # assign return values to response object
        resp = authorisationResponseWrapper()
        
                
        try:
            # Decrypt and parse input
            reqKeys = AuthorisationReq(xmlTxt=reqTxt,
                                     encrPriKeyFilePath=self.__srv['keyFile'],
                                     encrPriKeyPwd=self.__srv['keyPwd'])

            # Make request to local instance
            attCert = self.__srv.authorise(**reqKeys.xmlTags)
            
            authResp = AuthorisationResp(\
                                    credential=attCert,
                                    statCode=AuthorisationResp.accessGranted)
            
        except AttAuthorityAccessDenied, e:
            authResp = AuthorisationResp(errMsg=str(e),
                                    statCode=AuthorisationResp.accessDenied)
            
        except Exception, e:
            authResp = AuthorisationResp(errMsg=str(e),
                                    statCode=AuthorisationResp.accessError)


        try:
            # Encrypt response and convert into XML formatted string
            if 'encrCert' in reqKeys:
                
                # ConnectResp class expects the public key to be in a file
                # - Copy public key string content into a temporary file
                encrCertTmpFile = tempfile.NamedTemporaryFile()                    
                open(encrCertTmpFile.name, "w").write(reqKeys['encrCert'])
    
                authResp.encrypt(encrPubKeyFilePath=encrCertTmpFile.name)
                
        except Exception, e:
            authResp = AuthorisationResp(\
                                      statCode=AuthorisationResp.accessError,
                                      errMsg=str(e))

        
        # Convert response into encrypted XML formatted string    
        resp._authorisationResp = authResp()                                                            
        return resp


    #_________________________________________________________________________
    def soap_getPubKey(self, ps):
        """Get session manager public key in order to initiate a encrypted
        request"""
        
        if self.__debug:
            import pdb
            pdb.set_trace()
       
        # assign return values to response object
        resp = pubKeyResponseWrapper()

        try:
            # Get public key file and read into string     
            pubKey = open(self.__srv['certFile']).read()
            pubKeyResp = PubKeyResp(pubKey=pubKey)
            
        except IOError, (errNo, errMsg):
            pubKeyResp = PubKeyResp(errMsg="Reading public key \"%s\": %s" % \
                                    (self.__srv['certFile'], errMsg))                
        except Exception, e:
            pubKeyResp = PubKeyResp(errMsg=str(e))

        
        # Convert response into encrypted XML formatted string    
        resp._pubKeyResp = pubKeyResp()                                                            
        return resp
        