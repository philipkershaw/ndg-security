#!/usr/bin/env python

"""NDG Security client - client interface classes to Session Manager and 
Attribute Authority Web Services.  

Make requests for authentication and authorisation

NERC Data Grid Project

P J Kershaw 24/04/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

from ZSI import ServiceProxy
import sys
import os
from Cookie import SimpleCookie

# Handle retrieval of public key cert for Session Manager/Attribute Authority
# at remote location
import tempfile
import urllib

from NDG.X509 import *
import NDG.SessionMgrIO as smIO
import NDG.AttAuthorityIO as aaIO


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
    
    #_________________________________________________________________________
    def __init__(self, 
                 smWSDL=None, 
                 smPubKeyFilePath=None,
                 clntPubKeyFilePath=None,
                 clntPriKeyFilePath=None,
                 traceFile=None):
        """
        smWSDL:                  WSDL URI for Session Manager WS.  Setting it 
                                 will set the Service Proxy
        smPubKeyFilePath:    
                                 Public key of Session Manager used to encrypt
                                 the outgoing message if required - set as a
                                 path on the local file system or as a URI
        clntPubKeyFilePath:      Public key of client.  This is passed to the
                                 Session Manager so that it can encrypt
                                 responses.  WARNING: if not set, responses
                                 are returned as clear text
        clntPriKeyFilePath:      Private key of client.  If clntPubKeyFilePath
                                 is set, the private key is needed to decrypt 
                                 the response from the Session Manager
        traceFile:               set to file object such as sys.stderr to 
                                 give extra WS debug information"""

        self.__smSrv = None
        self.__smWSDL = None
        self.__smPubKeyFilePath = None
        self.__smPubKeyFilePath = None
        self.__clntPubKeyFilePath = None
        self.__clntPubKey = None
        self.__clntPriKeyFilePath = None
        
        self.__smPubKeyTempFile = None
        
        
        if smWSDL:
            self.__setSMwsdl(smWSDL)
            
        if smPubKeyFilePath:
            self.__setSMpubKeyFilePath(smPubKeyFilePath)
            
        if clntPriKeyFilePath:
            self.__setClntPriKeyFilePath(clntPriKeyFilePath)
            
        if clntPubKeyFilePath:
            if clntPriKeyFilePath is None:
                raise SessionClientError(\
                    "A Client private key file is required as well a " + \
                    "public key")
                    
            self.__setClntPubKeyFilePath(clntPubKeyFilePath)

           
        self.__traceFile = traceFile

         
        # Instantiate Session Manager WS proxy
        if self.__smWSDL:
            self.serviceProxy()
        

    #_________________________________________________________________________
    def __setSMwsdl(self, smWSDL):
        
        if not isinstance(smWSDL, basestring):
            raise SessionClientError(\
                            "Session Manager WSDL URI must be a valid string")
        
        self.__smWSDL = smWSDL
        
    smWSDL = property(fset=__setSMwsdl, doc="Set Session Manager WSDL URI")


    #_________________________________________________________________________
    def __setSMpubKeyFilePath(self, smPubKeyFilePath):
        
        if not isinstance(smPubKeyFilePath, basestring):
            raise SessionClientError(\
                "Session Manager public key URI must be a valid string")
        
        self.__smPubKeyFilePath = smPubKeyFilePath
        
    smPubKeyFilePath = property(fset=__setSMpubKeyFilePath,
                           doc="Set Session Manager public key URI")

 
    #_________________________________________________________________________
    def __setClntPubKeyFilePath(self, clntPubKeyFilePath):
        
        if not isinstance(clntPubKeyFilePath, basestring):
            raise SessionClientError(\
                "Client public key file path must be a valid string")
        
        self.__clntPubKeyFilePath = clntPubKeyFilePath
        try:
            self.__clntPubKey = open(self.__clntPubKeyFilePath).read()
            
        except IOError, (errNo, errMsg):
            raise SessionClientError(\
                    "Reading certificate file \"%s\": %s" % \
                    (self.__clntPubKeyFilePath, errMsg))
                               
        except Exception, e:
            raise SessionClientError(\
                    "Reading certificate file \"%s\": %s" % \
                    (self.__clntPubKeyFilePath, str(e)))
        
    clntPubKeyFilePath = property(fset=__setClntPubKeyFilePath,
                                  doc="File path for client public key")

 
    #_________________________________________________________________________
    def __setClntPriKeyFilePath(self, clntPriKeyFilePath):
        
        if not isinstance(clntPriKeyFilePath, basestring):
            raise SessionClientError(\
                "Client public key file path must be a valid string")
        
        self.__clntPriKeyFilePath = clntPriKeyFilePath
        
    clntPriKeyFilePath = property(fset=__setClntPriKeyFilePath,
                                  doc="File path for client private key")


    #_________________________________________________________________________
    def __getSessionMgrPubKey(self):
        """Retrieve the public key from the URI"""
        
        # Don't proceed unless URI was set - user may have set public key via
        # smPubKeyFilePath instead
        if self.__smPubKeyFilePath is not None:
            return
                
        try:
            self.__smPubKeyTempFile = tempfile.NamedTemporaryFile()
            
            pubKey = self.getPubKey()
            open(self.__smPubKeyTempFile.name, "w").write(pubKey)
            
            self.__smPubKeyFilePath = self.__smPubKeyTempFile.name
            
        except IOError, (errNo, errMsg):
            raise SessionClientError(\
                                "Writing public key to temp \"%s\": %s" % \
                                (self.__smPubKeyTempFile.name, errMsg))                                                                      
        except Exception, e:
            raise SessionClientError("Retrieving Session Manager " + \
                                     "public key: %s" % str(e))
    
        
    #_________________________________________________________________________
    def serviceProxy(self, smWSDL=None):
        """Set the WS proxy for the Session Manager"""
        if smWSDL:
            self.__setSMwsdl(smWSDL)

        try:
            self.__smSrv = ServiceProxy(self.__smWSDL, 
                                        use_wsdl=True, 
                                        tracefile=self.__traceFile)
        except Exception, e:
            raise SessionClientError("Initialising WSDL Service Proxy: " + \
                                     str(e))

                                    
    #_________________________________________________________________________
    def addUser(self,
                userName,
                pPhrase=None,
                pPhraseFilePath=None,
                clntPriKeyPwd=None):
        """Register a new user
        
        userName:                the username for the new user 
        pPhrase:                 user's pass-phrase
        pPhraseFilePath:         a file containing the user's pass-phrase.  
                                 Use this as an alternative to pPhrase keyword
        clntPriKeyPwd:           pass-phrase if any for the client's private
                                 key used to decrypt response from
                                 Session Manager
        """
    
        if pPhrase is None:
            try:
                pPhrase = open(pPhraseFilePath).read().strip()
            
            except Exception, e:
                raise SessionClientError("Pass-phrase not defined: " + str(e))


        # If Public key was not set, retrieve from server
        self.__getSessionMgrPubKey()
            
    
        # Make request for new user
        try:   
            addUserReq = smIO.AddUserReq(userName=userName, 
                                pPhrase=pPhrase,
                                encrCert=self.__clntPubKey,
                                encrPubKeyFilePath=self.__smPubKeyFilePath) 

            # Pass encrypted request
            resp = self.__smSrv.addUser(addUserReq=addUserReq())
                        
            addUserResp = smIO.AddUserResp(xmlTxt=resp['addUserResp'],
                                encrPriKeyFilePath=self.__clntPriKeyFilePath,
                                encrPriKeyPwd=clntPriKeyPwd)            
        except Exception, e:
            raise SessionClientError("Error adding new user: " + str(e))
  
                            
        if 'errMsg' in addUserResp and addUserResp['errMsg']:
            raise SessionClientError(addUserResp['errMsg'])
    
        
    #_________________________________________________________________________   
    def connect(self,
                userName,
                pPhrase=None,
                pPhraseFilePath=None,
                getCookie=True,
                createServerSess=False,
                clntPriKeyPwd=None):
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
        clntPriKeyPwd:           pass-phrase if any for the client's private
                                 key used to decrypt response from
                                 Session Manager."""
    
        if pPhrase is None:
            try:
                pPhrase = open(pPhraseFilePath).read().strip()
            
            except Exception, e:
                raise SessionClientError("Pass-phrase not defined: " + str(e))


        # If Public key was not set, retrieve from server
        self.__getSessionMgrPubKey()

        
        # Make connection
        try: 
            connectReq = smIO.ConnectReq(userName=userName, 
                                pPhrase=pPhrase,
                                getCookie=getCookie,
                                createServerSess=createServerSess,
                                encrCert=self.__clntPubKey,
                                encrPubKeyFilePath=self.__smPubKeyFilePath) 
    
            # Pass encrypted request
            resp = self.__smSrv.connect(connectReq=connectReq())
            
            connectResp = smIO.ConnectResp(xmlTxt=resp['connectResp'],
                                encrPriKeyFilePath=self.__clntPriKeyFilePath,
                                encrPriKeyPwd=clntPriKeyPwd)
                            
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
                         proxyCert=None,
                         sessCookie=None,
                         sessID=None,
                         encrSessMgrWSDLuri=None,
                         aaWSDL=None,
                         aaPubKey=None,
                         reqRole=None,
                         mapFromTrustedHosts=None,
                         rtnExtAttCertList=None,
                         extAttCertList=None,
                         extTrustedHostList=None,
                         clntPriKeyPwd=None):    
        """Request authorisation from NDG Session Manager Web Service.
        
        reqAuthorisation([sessCookie=s]|[sessID=i, encrSessMgrWSDLuri=e]|
                         [proxyCert=p][key=arg, ...])
        proxyCert:             proxy certificate - use as ID instead of 
                               a cookie in the case of a command line client.
        sessCookie:            session cookie returned from call to connect() 
                               for a browser client.  Input as a string or
                               SimpleCookie type.
        sessID:                session ID.  Input this as well as 
                               encrSessMgrWSDLuri as an alternative to 
                               sessCookie in the case of a browser client.
        encrSessMgrWSDLuri:    encrypted Session Manager WSDL URI.
        aaWSDL:                WSDL URI for Attribute Authority WS.
        aaPubKey:              The Session Manager uses the Public key of the
                               Attribute Authority to encrypt requests to it.
        reqRole:               The required role for access to a data set.
                               This can be left out in which case the 
                               Attribute Authority just returns whatever
                               Attribute Certificate it has for the user
        mapFromTrustedHosts:   Allow a mapped Attribute Certificate to be
                               created from a user certificate from another
                               trusted host.
        rtnExtAttCertList:     Set this flag True so that if authorisation is 
                               denied, a list of potential attribute 
                               certificates for mapping may be returned. 
        extAttCertList:        A list of Attribute Certificates from other
                               trusted hosts from which the target Attribute
                               Authority can make a mapped certificate
        extTrustedHostList:    A list of trusted hosts that can be used to
                               get Attribute Certificates for making a mapped
                               AC.
        clntPriKeyPwd:         pass-phrase if any for the client's private
                               key used to decrypt response from
                               Session Manager.
        """
        
        if sessCookie:
            if isinstance(sessCookie, basestring):
                try:
                    sessCookie = SimpleCookie(sessCookie)
                except Exception, e:
                    raise SessionClientError(\
                                    "Error parsing session cookie: " + str(e))

            sessID = sessCookie['NDG-ID1'].value
            encrSessMgrWSDLuri = sessCookie['NDG-ID2'].value
            
        elif not sessID and not encrSessMgrWSDLuri and not proxyCert:
            raise SessionClientError(\
                '"proxyCert" or "sessCookie or "sessID" and ' + \
                '"encrSessMgrWSDLuri" keywords must be set')


        # If Public key was not set, retrieve from server
        self.__getSessionMgrPubKey()

            
        # Make authorisation request
        try:
            authReq = smIO.AuthorisationReq(aaWSDL=aaWSDL,
                                 aaPubKey=aaPubKey,
                                 sessID=sessID, 
                                 encrSessMgrWSDLuri=encrSessMgrWSDLuri,
                                 proxyCert=proxyCert,
                                 reqRole=reqRole,
                                 mapFromTrustedHosts=mapFromTrustedHosts,
                                 rtnExtAttCertList=rtnExtAttCertList,
                                 extAttCertList=extAttCertList,
                                 extTrustedHostList=extTrustedHostList,
                                 encrCert=self.__clntPubKey,
                                 encrPubKeyFilePath=self.__smPubKeyFilePath) 
                                            
            resp = self.__smSrv.reqAuthorisation(authorisationReq=authReq())
            authResp = smIO.AuthorisationResp(xmlTxt=resp['authorisationResp'],
                                encrPriKeyFilePath=self.__clntPriKeyFilePath,
                                encrPriKeyPwd=clntPriKeyPwd)
            return authResp
            
        except Exception, e:
            raise SessionClientError(\
                                "Error in authorisation request: " + str(e))

                                    
    #_________________________________________________________________________
    def getPubKey(self):
        """Retrieve the public key of the Session Manager"""
        
        try:   
            pubKeyReq = smIO.PubKeyReq() 

            # Pass request
            resp = self.__smSrv.getPubKey(pubKeyReq=pubKeyReq())
                        
            pubKeyResp = smIO.PubKeyResp(xmlTxt=resp['pubKeyResp'])
                            
            if 'errMsg' in pubKeyResp and pubKeyResp['errMsg']:
                raise SessionClientError(pubKeyResp['errMsg'])
            
            return pubKeyResp['pubKey']
        
        except Exception, e:
            raise SessionClientError("Error retrieving public key: " + str(e))




#_____________________________________________________________________________
class AttAuthorityClientError(Exception):
    """Exception handling for SessionClient class"""
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class AttAuthorityClient(object):
    
    #_________________________________________________________________________
    def __init__(self, 
                 aaWSDL=None, 
                 aaPubKeyFilePath=None,
                 clntPubKeyFilePath=None,
                 clntPriKeyFilePath=None,
                 traceFile=None):
        """
        aaWSDL:                  WSDL URI for Attribute Authority WS.  Setting 
                                 it will set the Service Proxy
        aaPubKeyFilePath:    
                                 Public key of Attribute Authority used to 
                                 encrypt the outgoing message if required - 
                                 set as a path on the local file system or as 
                                 a URI
        clntPubKeyFilePath:      Public key of client.  This is passed to the
                                 Attribute Authority so that it can encrypt
                                 responses.  WARNING: if not set, responses
                                 are returned as clear text
        clntPriKeyFilePath:      Private key of client.  If clntPubKeyFilePath
                                 is set, the private key is needed to decrypt 
                                 the response from the Attribute Authority
        traceFile:               set to file object such as sys.stderr to 
                                 give extra WS debug information"""

        self.__aaSrv = None
        self.__aaWSDL = None
        self.__aaPubKeyFilePath = None
        self.__aaPubKeyFilePath = None
        self.__clntPubKeyFilePath = None
        self.__clntPubKey = None
        self.__clntPriKeyFilePath = None
        
        self.__aaPubKeyTempFile = None
        
        
        if aaWSDL:
            self.__setAAwsdl(aaWSDL)
            
        if aaPubKeyFilePath:
            self.__setAApubKeyFilePath(aaPubKeyFilePath)
            
        if clntPriKeyFilePath:
            self.__setClntPriKeyFilePath(clntPriKeyFilePath)
            
        if clntPubKeyFilePath:
            if clntPriKeyFilePath is None:
                raise AttAuthorityClientError(\
                    "A Client private key file is required as well a " + \
                    "public key")
                    
            self.__setClntPubKeyFilePath(clntPubKeyFilePath)

           
        self.__traceFile = traceFile

         
        # Instantiate Attribute Authority WS proxy
        if self.__aaWSDL:
            self.serviceProxy()
        

    #_________________________________________________________________________
    def __setAAwsdl(self, aaWSDL):
        
        if not isinstance(aaWSDL, basestring):
            raise AttAuthorityClientError(\
                        "Attribute Authority WSDL URI must be a valid string")
        
        self.__aaWSDL = aaWSDL
        
    aaWSDL = property(fset=__setAAwsdl,doc="Set Attribute Authority WSDL URI")


    #_________________________________________________________________________
    def __setAApubKeyFilePath(self, aaPubKeyFilePath):
        
        if not isinstance(aaPubKeyFilePath, basestring):
            raise AttAuthorityClientError(\
                "Attribute Authority public key URI must be a valid string")
        
        self.__aaPubKeyFilePath = aaPubKeyFilePath
        
    aaPubKeyFilePath = property(fset=__setAApubKeyFilePath,
                           doc="Set Attribute Authority public key URI")

 
    #_________________________________________________________________________
    def __setClntPubKeyFilePath(self, clntPubKeyFilePath):
        
        if not isinstance(clntPubKeyFilePath, basestring):
            raise AttAuthorityClientError(\
                "Client public key file path must be a valid string")
        
        self.__clntPubKeyFilePath = clntPubKeyFilePath
        try:
            self.__clntPubKey = open(self.__clntPubKeyFilePath).read()
            
        except IOError, (errNo, errMsg):
            raise AttAuthorityClientError(\
                    "Reading certificate file \"%s\": %s" % \
                    (self.__clntPubKeyFilePath, errMsg))
                               
        except Exception, e:
            raise AttAuthorityClientError(\
                    "Reading certificate file \"%s\": %s" % \
                    (self.__clntPubKeyFilePath, str(e)))
        
    clntPubKeyFilePath = property(fset=__setClntPubKeyFilePath,
                                  doc="File path for client public key")

 
    #_________________________________________________________________________
    def __setClntPriKeyFilePath(self, clntPriKeyFilePath):
        
        if not isinstance(clntPriKeyFilePath, basestring):
            raise AttAuthorityClientError(\
                "Client public key file path must be a valid string")
        
        self.__clntPriKeyFilePath = clntPriKeyFilePath
        
    clntPriKeyFilePath = property(fset=__setClntPriKeyFilePath,
                                  doc="File path for client private key")


    #_________________________________________________________________________
    def __getAttAuthorityPubKey(self):
        """Retrieve the public key from the URI"""
        
        # Don't proceed unless URI was set - user may have set public key via
        # aaPubKeyFilePath instead
        if self.__aaPubKeyFilePath is not None:
            return
                
        try:
            self.__aaPubKeyTempFile = tempfile.NamedTemporaryFile()
            
            pubKey = self.getPubKey()
            open(self.__aaPubKeyTempFile.name, "w").write(pubKey)
            
            self.__aaPubKeyFilePath = self.__aaPubKeyTempFile.name
            
        except IOError, (errNo, errMsg):
            raise AttAuthorityClientError(\
                                "Writing public key to temp \"%s\": %s" % \
                                (self.__aaPubKeyTempFile.name, errMsg))                                                                      
        except Exception, e:
            raise AttAuthorityClientError("Retrieving Attribute Authority " +\
                                          "public key: %s" % str(e))
    
        
    #_________________________________________________________________________
    def serviceProxy(self, aaWSDL=None):
        """Set the WS proxy for the Attribute Authority"""
        if aaWSDL:
            self.__setAAwsdl(aaWSDL)

        try:
            self.__aaSrv = ServiceProxy(self.__aaWSDL, 
                                        use_wsdl=True, 
                                        tracefile=self.__traceFile)
        except Exception, e:
            raise AttAuthorityClientError(\
                    "Initialising WSDL Service Proxy: " + str(e))

                                    
    #_________________________________________________________________________
    def getTrustedHostInfo(self, role=None, clntPriKeyPwd=None):
        """Get list of trusted hosts for an Attribute Authority
        
        """

        # If Public key was not set, retrieve from server
        self.__getAttAuthorityPubKey()
            
    
        # Make request for new user
        try:   
            trustedHostInfoReq = aaIO.TrustedHostInfoReq(role=role, 
                                encrCert=self.__clntPubKey,
                                encrPubKeyFilePath=self.__aaPubKeyFilePath) 

            # Pass encrypted request
            resp = self.__aaSrv.getTrustedHostInfo(\
                                    trustedHostInfoReq=trustedHostInfoReq())
                        
            trustedHostInfoResp = aaIO.TrustedHostInfoResp(\
                                xmlTxt=resp['trustedHostInfoResp'],
                                encrPriKeyFilePath=self.__clntPriKeyFilePath,
                                encrPriKeyPwd=clntPriKeyPwd)            
        except Exception, e:
            raise AttAuthorityClientError("Error: " + str(e))
  
                            
        if 'errMsg' in trustedHostInfoResp and trustedHostInfoResp['errMsg']:
            raise AttAuthorityClientError(trustedHostInfoResp['errMsg'])

        return trustedHostInfoResp['trustedHosts']
    

    #_________________________________________________________________________
    def reqAuthorisation(self, 
                         proxyCert, 
                         userAttCert=None, 
                         clntPriKeyPwd=None):
        """Request authorisation from NDG Attribute Authority Web Service."""


        # If Public key was not set, retrieve from server
        self.__getAttAuthorityPubKey()


        try:   
            authReq = aaIO.AuthorisationReq(proxyCert=proxyCert,
                                 userAttCert=userAttCert,
                                 encrCert=self.__clntPubKey,
                                 encrPubKeyFilePath=self.__aaPubKeyFilePath) 

            resp = self.__aaSrv.reqAuthorisation(authorisationReq=authReq())
                                      
            authResp=aaIO.AuthorisationResp(xmlTxt=resp['authorisationResp'],
                                encrPriKeyFilePath=self.__clntPriKeyFilePath,
                                encrPriKeyPwd=clntPriKeyPwd)           
        except Exception, e:
            raise AttAuthorityClientError("Error: " + str(e))
            
        if 'errMsg' in authResp and authResp['errMsg']:
            raise AttAuthorityClientError(resp['errMsg'])
        
        return authResp

                                    
    #_________________________________________________________________________
    def getPubKey(self):
        """Retrieve the public key of the Session Manager"""
        
        try:   
            pubKeyReq = aaIO.PubKeyReq() 

            # Pass request
            resp = self.__aaSrv.getPubKey(pubKeyReq=pubKeyReq())
                        
            pubKeyResp = aaIO.PubKeyResp(xmlTxt=resp['pubKeyResp'])
                            
            if 'errMsg' in pubKeyResp and pubKeyResp['errMsg']:
                raise AttAuthorityClientError(pubKeyResp['errMsg'])
            
            return pubKeyResp['pubKey']
        
        except Exception, e:
            raise AttAuthorityClientError(\
                                    "Error retrieving public key: " + str(e))                              