#!/usr/bin/env python

"""NDG Session client - makes requests for authentication and authorisation

NERC Data Grid Project

P J Kershaw 16/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

from ZSI import ServiceProxy
import sys
import os
from Cookie import SimpleCookie

from X509 import *
from SessionMgrIO import *


#_____________________________________________________________________________
class SessionClientError(Exception):
    """Exception handling for SessionClient class"""
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________       
class SessionClient(object):
    """Client interface to Session Manager Web Service"""
    
    def __init__(self, 
                 smWSDL=None, 
                 smEncrPubKeyFilePath=None,
                 traceFile=None):
        """
        smWSDL:                  WSDL URI for Session Manager WS.  Setting it 
                                 will set the Service Proxy
        smEncrPubKeyFilePath:    Public key of Session Manager used to encrypt
                                 the outgoing message if required
        traceFile:               set to file object such as sys.stderr to 
                                 give extra WS debug information"""

        if smWSDL:
            self.__setSMwsdl(smWSDL)
        else:
            self.__smWSDL = None
            
        if smEncrPubKeyFilePath:
            self.__setSMencrPubKeyFilePath(smEncrPubKeyFilePath)
        else:
            self.__smEncrPubKeyFilePath = None
                
        self.__traceFile = traceFile

         
        # Instantiate Session Manager WS proxy
        if self.__smWSDL:
            self.serviceProxy()
        

    def __setSMwsdl(self, smWSDL):
        
        if not isinstance(smWSDL, basestring):
            raise SessionClientError(\
                            "Session Manager WSDL URI must be a valid string")
        
        self.__smWSDL = smWSDL
        
    smWSDL = property(fset=__setSMwsdl,
                      doc="Set Session Manager WSDL URI")
                      
    
    def __setSMencrPubKeyFilePath(self, smEncrPubKeyFilePath):
        
        if not isinstance(smEncrPubKeyFilePath, basestring):
            raise SessionClientError(\
                "Session Manager public key file path must be a valid string")
        
        self.__smEncrPubKeyFilePath = smEncrPubKeyFilePath
        
    smEncrPubKeyFilePath = property(fset=__setSMencrPubKeyFilePath,
                            doc="Set Session Manager public key file path")

        
    #_________________________________________________________________________
    def serviceProxy(self, smWSDL=None):
        """Set the WS proxy for the Session Manager"""
        if smWSDL:
            self.__setSMwsdl(smWSDL)

        self.__smSrv = ServiceProxy(self.__smWSDL, 
                                    use_wsdl=True, 
                                    tracefile=self.__traceFile)

                                    
    #_________________________________________________________________________
    def addUser(self,
                userName,
                pPhrase=None,
                pPhraseFilePath=None,
                smWSDL=None,
                smEncrPubKeyFilePath=None):
        """Register a new user
        
        userName:                the username for the new user 
        pPhrase:                 user's pass-phrase
        pPhraseFilePath:         a file containing the user's pass-phrase.  
                                 Use this as an alternative to pPhrase keyword
        smWSDL:                  WSDL URI for Session Manager WS.  Setting it 
                                 will reset the Service Proxy
        smEncrPubKeyFilePath:    Public key of Session Manager used to encrypt
                                 the outgoing message if required"""
    
        if smWSDL:
            self.serviceProxy(smWSDL)
            
        if smEncrPubKeyFilePath:
            self.__setSMencrPubKeyFilePath(smEncrPubKeyFilePath)

            
        if pPhrase is None:
            try:
                pPhrase = open(pPhraseFilePath).read().strip()
            
            except Exception, e:
                raise SessionClientError("Pass-phrase not defined: " + str(e))
            
    
        # Make request for new user
        try:   
            addUserReq = AddUserReq(userName=userName, 
                                    pPhrase=pPhrase,
                                    encrPubKeyFilePath=smEncrPubKeyFilePath) 

            # Pass encrypted request
            resp = self.__smSrv.addUser(addUserReq=addUserReq())            
            addUserResp = AddUserResp(xmlTxt=str(resp['addUserResp']))
            if 'errMsg' in addUserResp and addUserResp['errMsg']:
                raise SessionClientError(addUserResp['errMsg'])
            
        except Exception, e:
            raise SessionClientError("Error adding new user: " + str(e))
    
        
    #_________________________________________________________________________   
    def connect(self,
                userName,
                pPhrase=None,
                pPhraseFilePath=None,
                getCookie=True,
                createServerSess=False,
                smWSDL=None,
                smEncrPubKeyFilePath=None):
        """Request a new user session from the Session Manager
        
        userName:                the username of the user to connect
        pPhrase:                 user's pass-phrase
        pPhraseFilePath:         a file containing the user's pass-phrase.  
                                 Use this as an alternative to pPhrase 
                                 keyword.
                                 
        getCookie:               If set to true, return a cookie to be set in 
                                 a web browser client.  Otherwise, return a 
                                 proxy certificate.
                                 
        createServerSess:        If set to True, the SessionMgr will create
                                 and manage a session for the user but note,
                                 this flag is ignored and set to True if
                                 getCookie is set.  
                                 
                                 For command line case, where getCookie is 
                                 False, it's possible to choose to have a 
                                 client or server side session using this 
                                 keyword.
                                 
        smWSDL:                  WSDL URI for Session Manager WS.  Setting it 
                                 will reset the Service Proxy.
                                 
        smEncrPubKeyFilePath:    Public key of Session Manager used to encrypt
                                 the outgoing message if required"""
    
        if smWSDL:
            self.serviceProxy(smWSDL)
            
        if smEncrPubKeyFilePath:
            self.__setSMencrPubKeyFilePath(smEncrPubKeyFilePath)
            
        if pPhrase is None:
            try:
                pPhrase = open(pPhraseFilePath).read().strip()
            
            except Exception, e:
                raise SessionClientError("Pass-phrase not defined: " + str(e))
            
    
        # Make connection
        try: 
            connectReq = ConnectReq(userName=userName, 
                            pPhrase=pPhrase,
                            getCookie=getCookie,
                            createServerSess=createServerSess,
                            encrPubKeyFilePath=self.__smEncrPubKeyFilePath) 
    
            # Pass encrypted request
            resp = self.__smSrv.connect(connectReq=connectReq())
            connectResp = ConnectResp(xmlTxt=str(resp['connectResp']))
            if 'errMsg' in connectResp and connectResp['errMsg']:
                raise Exception(connectResp['errMsg'])
            
            if 'sessCookie' in connectResp:
                return connectResp['sessCookie']
            
            elif 'proxyCert' in connectResp:
                return connectResp['proxyCert']
            
            else:
               raise SessionClientError(\
               "Neither \"sessCookie\" or \"proxyCert\" found in response")
               
        except Exception, e:
            raise SessionClientError(\
                            "Error connecting to Session Manager: " + str(e))
    
    
    #_________________________________________________________________________ 
    def reqAuthorisation(self,
                         sessID=None,
                         encrSessMgrWSDLuri=None,
                         proxyCert=None,
                         smWSDL=None,
                         aaWSDL=None,
                         reqRole=None,
                         mapFromTrustedHosts=False,
                         rtnExtAttCertList=False,
                         extAttCertList=None,
                         extTrustedHostList=None,
                         encrCert=None,
                         smEncrPubKeyFilePath=None):    
        """Request authorisation from NDG Session Manager Web Service.
        
        sessID:                session ID returned with cookie from connect()
        encrSessMgrWSDLuri:    encrypted Session Manager WSDL URI.  This is
                               also returned in a cookie from a previous call
                               to connect.  The Session Manager WS called -
                               as set in self.__smWSDL - will decrypt and 
                               check encrSessMgrWSDLuri.  If the URI 
                               corresponds to a different Session Manager, it
                               will re-direct the request there.
        proxyCert:             proxy certificate - use as ID instead of 
                               session ID + encrSessMgrWSDLuri in the case of
                               command line client.
        smWSDL:                WSDL URI for Session Manager WS call this may
                               not be the same as the encrypted address in
                               encrSessMgrWSDLuri.  If set a new Service
                               Proxy will be set up.
        reqRole:               The required role for access to a data set.
                               This can be left out in which case the 
                               Attribute Authority just returns whatever
                               Attribute Certificate it has for the user
        mapFromTrustedHosts:   Allow a mapped Attribute Certificate to be
                               created from a user certificate from another
                               trusted host
        rtnExtAttCertList:     Set this flag True so that if authorisation is 
                               denied, a list of potential attribute 
                               certificates for mapping may be returned. 
        extAttCertList:        A list of Attribute Certificates from other
                               trusted hosts from which the target Attribute
                               Authority can make a mapped certificate
        extTrustedHostList:    A list of trusted hosts that can be used to
                               get Attribute Certificates for making a mapped
                               AC
        encrCert:              A public key for the client to enable the
                               Session Manager to encrypt its reply to this
                               call
        """
           
        if smWSDL:
            # Instantiate WS proxy
            self.serviceProxy(smWSDL)
            
        if smEncrPubKeyFilePath:
            self.__setSMencrPubKeyFilePath(smEncrPubKeyFilePath)
    
            
        # Make authorisation request
        try:
            authReq=AuthorisationReq(aaWSDL=aaWSDL,
                             sessID=sessID,
                             encrSessMgrWSDLuri=encrSessMgrWSDLuri,
                             proxyCert=proxyCert,
                             reqRole=reqRole,
                             mapFromTrustedHosts=mapFromTrustedHosts,
                             rtnExtAttCertList=rtnExtAttCertList,
                             extAttCertList=extAttCertList,
                             extTrustedHostList=extTrustedHostList,
                             encrCert=encrCert,
                             encrPubKeyFilePath=self.__smEncrPubKeyFilePath) 
                                            
            resp = self.__smSrv.reqAuthorisation(authorisationReq=authReq())
            authResp = AuthorisationResp(\
                                        xmlTxt=str(resp['authorisationResp']))
            return authResp
            
        except Exception, e:
            raise SessionClientError(\
                                "Error in authorisation request: " + str(e))

    
#_____________________________________________________________________________
if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == '-d':
        import pdb
        pdb.set_trace()

    try:
        
        aaWSDL = 'http://glue.badc.rl.ac.uk/attAuthority.wsdl'
        
        # Session Manager WSDL
        #smWSDL = 'http://livglue.nerc-liv.ac.uk/sessionMgr.wsdl'
        smWSDL = 'http://glue.badc.rl.ac.uk/sessionMgr.wsdl'
        
        # Public key of session manager used to encrypt requests
        smEncrPubKeyFilePath = None#'../certs/badc-sm-cert.pem'
        
        userName = 'pjkbodc'#'pjkersha'

        sessClnt = SessionClient(smWSDL=smWSDL,
                                 smEncrPubKeyFilePath=smEncrPubKeyFilePath,
                                 traceFile=sys.stderr)
        
#        sessClnt.addUser(userName, pPhraseFilePath="../tmp")
        sSessCookie = sessClnt.connect(userName, pPhraseFilePath="../tmp")
#        sessCookie = SimpleCookie(sSessCookie)
#        authResp = sessClnt.reqAuthorisation(sessCookie['NDG-ID1'].value, 
#                                             sessCookie['NDG-ID2'].value,
#                                             aaWSDL=aaWSDL)
        print authResp
        
    except Exception, e:
        sys.stderr.write(str(e) + os.linesep)
        sys.exit(1)
        
