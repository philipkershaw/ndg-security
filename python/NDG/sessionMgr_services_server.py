"""NDG Session Manager Web service server side interface.  Generated and 
adapted from:

wsdl2dispatch -f sessionMgr.wsdl

NERC Data Grid Project

P J Kershaw 18/12/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

from ZSI.ServiceContainer import ServiceSOAPBinding

# wsdl2py generated
from sessionMgr_services import *

from Session import *

# Create custom XML formatted error response where needed
from SessionMgrIO import *


class sessionMgr(ServiceSOAPBinding):
    soapAction = {
        'urn:sessionMgr#addUser': 'soap_addUser',
        'urn:sessionMgr#connect': 'soap_connect',
        'urn:sessionMgr#reqAuthorisation': 'soap_reqAuthorisation',
        'urn:sessionMgr#getPubKey': 'soap_getPubKey',
        }

    def __init__(self, srv, debug=False, post='/sessionMgr.wsdl', **kw):
        
        ServiceSOAPBinding.__init__(self, post)

        # Link WS to underlying session manager class instance
        if not isinstance(srv, SessionMgr):
            SessionMgrError("Expecting SessionMgr type")
            
        self.__srv = srv
        
        self.__debug = debug
        
        
    #_________________________________________________________________________
    def soap_addUser(self, ps):
        """SOAP interface to NDG Session Manager WS addUser."""
       
        if self.__debug:
            import pdb
            pdb.set_trace()

        # input vals in request object
        reqArgs = ps.Parse(addUserRequestWrapper)
        reqTxt = str(reqArgs._addUserReq)

        # assign return values to response object
        resp = addUserResponseWrapper()

        
        try:
            # Decrypt and parse input
            reqKeys = AddUserReq(xmlTxt=reqTxt,
                                 encrPriKeyFilePath=self.__srv['keyFile'],
                                 encrPriKeyPwd=self.__srv['keyPPhrase'])
       
            # New user request for Session Manager
            addUserResp = self.__srv.addUser(**reqKeys.xmlTags)

        except Exception, e:
            # Nb. catch exception here so that error message will be encrypted
            # if 'encrCert' key was set
            addUserResp = AddUserResp(errMsg=str(e))


        try:
            # Encrypt response and convert into XML formatted string
            if 'encrCert' in reqKeys:
                
                # ConnectResp class expects the public key to be in a file
                # - Copy public key string content into a temporary file
                encrCertTmpFile = tempfile.NamedTemporaryFile()                    
                open(encrCertTmpFile.name, "w").write(reqKeys['encrCert'])
    
                addUserResp.encrypt(encrPubKeyFilePath=encrCertTmpFile.name)
                
        except Exception, e:
            addUserResp = AddUserResp(errMsg=str(e))
        

        # Convert response into encrypted XML formatted string
        resp._addUserResp = addUserResp()
        return resp


    #_________________________________________________________________________
    def soap_connect(self, ps):
        """SOAP interface to NDG Session Manager WS connect."""
        
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        # input vals in request object
        reqArgs = ps.Parse(connectRequestWrapper)
        reqTxt = str(reqArgs._connectReq)

        # assign return values to response object
        resp = connectResponseWrapper()

        
        try:
            # Decrypt and parse input
            reqKeys = ConnectReq(xmlTxt=reqTxt,
                                 encrPriKeyFilePath=self.__srv['keyFile'],
                                 encrPriKeyPwd=self.__srv['keyPPhrase'])
       
            # Request a connection from the Session Manager
            connectResp = self.__srv.connect(**reqKeys.xmlTags) 

        except Exception, e:
            # Nb. catch exception here so that error message will be encrypted
            # if 'encrCert' key was set
            connectResp = ConnectResp(errMsg=str(e))


        try:
            # Encrypt response and convert into XML formatted string
            if 'encrCert' in reqKeys:
                
                # ConnectResp class expects the public key to be in a file
                # - Copy public key string content into a temporary file
                encrCertTmpFile = tempfile.NamedTemporaryFile()                    
                open(encrCertTmpFile.name, "w").write(reqKeys['encrCert'])
    
                connectResp.encrypt(encrPubKeyFilePath=encrCertTmpFile.name)
                
        except Exception, e:
            connectResp = ConnectResp(errMsg=str(e))
                   
                                        
        resp._connectResp = connectResp()        
        return resp


    #_________________________________________________________________________
    def soap_reqAuthorisation(self, ps):
        """Make an authorisation request via the session manager"""
        
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
                                     encrPriKeyPwd=self.__srv['keyPPhrase'])
            
            # Make request to local instance      
            authResp = self.__srv.reqAuthorisation(**reqKeys.xmlTags)

        except Exception, e:
            # Nb. catch exception here so that error message will be encrypted
            # if 'encrCert' key was set
            authResp = AuthorisationResp(\
                                    statCode=AuthorisationResp.accessError,
                                    errMsg=str(e))


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
