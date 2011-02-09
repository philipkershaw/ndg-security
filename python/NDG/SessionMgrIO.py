"""NDG Session Manager Web Services helper classes for I/O between client
and server

NERC Data Grid Project

P J Kershaw 14/12/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

# For new line symbol
import os

# Use _getframe to allow setting of attributes by derived class methods
import sys

# Filter out xml headers from returned attribute certificates in 
# AuthorisationResp
import re

from XMLMsg import *

# For use with AuthorisationResp class
from AttCert import *
 

#_____________________________________________________________________________
class ConnectReqError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS connect request class."""
    pass


#_____________________________________________________________________________
class ConnectReq(XMLMsg):
    """For client to Session Manager WS connect(): formats inputs for request
    into XML and encrypts.
    
    For Session Manager enables decryption of result"""
    
    # Override base class class variables
    xmlTagTmpl = {  "userName":              "",
                    "pPhrase":               "",
                    "proxyCert":             "",
                    "sessID":                "",
                    "getCookie":             "",
                    "createServerSess":      "",
                    "encrCert":              ""    }
                        

    def __init__(self, **xmlMsgKeys):
        """XML for sending encrypted credentials to Session Manager connect
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'userName' and 'pPhrase' or
                       'proxyCert' or 'sessID' must be input as the bare
                       minimum required for SessionMgr connect request.
        """
        
                               
        # Check for encrypted text or valid credentials
        if 'encrXMLtxt' not in xmlMsgKeys and 'xmlTxt' not in xmlMsgKeys:            

            # XML tags input as keywords expected - check minimum 
            # required are present for SessionMgr connect request
            if 'userName' not in xmlMsgKeys and 'pPhrase' not in xmlMsgKeys:
                if 'proxyCert' not in xmlMsgKeys:
                    if 'sessID' not in xmlMsgKeys:
                        raise ConnectReqError(\
                            "Credentials must be: \"userName\" and " + \
                            "\"pPhrase\" or \"proxyCert\" or \"sessID\"")
                
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to convert boolean"""
        
        rootElem = super(self.__class__, self).parseXML(rtnRootElem=True)
        
        if 'getCookie' in self:
            self['getCookie'] = bool(int(self['getCookie']))
            
        if 'createServerSess' in self:
            self['createServerSess'] = bool(int(self['createServerSess']))


#_____________________________________________________________________________
class ConnectRespError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS connect response class."""
    pass


#_____________________________________________________________________________
class ConnectResp(XMLMsg):
    """For client to Session Manager WS connect(): formats connect response
    from SessionMgr.
    
    For client, enables decryption of response"""
    
    # Override base class class variables
    xmlTagTmpl = {  "proxyCert":   "",
                    "sessCookie":  "",
                    "errMsg":      ""    }
                        

    def __init__(self, **xmlMsgKeys):
        """XML for receiving credentials from Session Manager connect call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'proxyCert' or 'sessCookie' 
                       must be set.                        
        """        
        
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
                               
        # Check for valid output credentials
        # XML tags input as keywords expected - check minimum 
        # required are present for SessionMgr connect response
        if 'proxyCert' not in self and 'sessCookie' not in self:            

            # If no proxy cert or session cookie then it must be an error
            if 'errMsg' not in self:
                raise ConnectRespError(\
                "Connect response document must contain: \"proxyCert\"" + \
                " or \"sessCookie\" keywords")
    

#_____________________________________________________________________________
class AddUserReqError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS connect request class."""
    pass


#_____________________________________________________________________________
class AddUserReq(XMLMsg):
    """For client to Session Manager WS addUser(): formats inputs for request
    into XML and encrypts.
    
    For Session Manager enables decryption of result"""
    
    # Override base class class variables
    xmlTagTmpl = {  "userName":    "",
                    "pPhrase":     "",
                    "encrCert":    ""    }
                        

    def __init__(self, **xmlMsgKeys):
        """XML for sending encrypted credentials to Session Manager connect
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'userName' and 'pPhrase' 
                       must be input as the bare minimum required for 
                       SessionMgr addUser request.
        """
        
                               
        # Check for encrypted text or valid credentials
        if 'encrXMLtxt' not in xmlMsgKeys and 'xmlTxt' not in xmlMsgKeys:            

            # XML tags input as keywords expected - check minimum 
            # required are present for SessionMgr connect request
            if 'userName' not in xmlMsgKeys and 'pPhrase' not in xmlMsgKeys:
                raise AddUserReqError(\
                    "Credentials must include \"userName\" and \"pPhrase\"")
                
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
     

#_____________________________________________________________________________
class AddUserRespError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS addUser response class."""
    pass


#_____________________________________________________________________________
class AddUserResp(XMLMsg):
    """For client to Session Manager WS connect(): formats addUser response
    from SessionMgr.
    
    For client, enables decryption of response"""
    
    # Override base class class variables
    xmlTagTmpl = {"errMsg": ""}
                        

    def __init__(self, **xmlMsgKeys):
        """XML for returning error status from Session Manager addUser()
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'proxyCert' or 'sessCookie' 
                       must be set.
        """
                
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
                               
        # Check valid output
        if 'errMsg' not in self:            

            # XML tags input as keywords expected - check minimum 
            # required are present for SessionMgr connect response
            raise AddUserRespError(\
                "AddUser response must contain \"errMsg\" keyword")
        

#_____________________________________________________________________________
class AuthorisationReqError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS authorisation request class.
    """
    pass


#_____________________________________________________________________________
class AuthorisationReq(XMLMsg):
    """For client to Session Manager WS reqAuthorisation(): formats inputs for
    request into XML and encrypts.
    
    Session Manager enables decryption of result"""
    
    # Override base class class variables
    xmlTagTmpl = {  "sessID":                 "",
                    "encrSessMgrWSDLuri":     "",
                    "proxyCert":              "",
                    "aaWSDL":                 "",
                    "aaPubKey":               "",
                    "reqRole":                "",
                    "mapFromTrustedHosts":    "",
                    "rtnExtAttCertList":      "",
                    "extAttCertList":         "",
                    "extTrustedHostList":     "",
                    "encrCert":               ""    }
                    
    # Regular expressions for parsing AttCerts from XML
    __attCertPat = re.compile(\
                    '<attributeCertificate>.*?</attributeCertificate>', re.S)
                    
    __extACListPat = re.compile('<extAttCertList>.*</extAttCertList>', re.S)


    def __init__(self, **xmlMsgKeys):
        """XML for sending encrypted credentials to Session Manager 
        authorisation request
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'userName' and 'pPhrase' or
                       'proxyCert' or 'sessID' must be input as the bare
                       minimum required for SessionMgr connect request.
        """
                       
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)

                               
        # Check for encrypted text or valid credentials
        if 'sessID' not in self and 'encrSessMgrWSDLuri' not in self:
            if 'proxyCert' not in self:
                raise AuthorisationReqError(\
                    "Authorisation request must include the credentials: " + \
                    "\"sessID\" and \"encrSessMgrWSDLuri\" or \"proxyCert\"")
                
        if 'aaWSDL' not in self:            
            raise AuthorisationReqError(\
                "Authorisation request must include: \"aaWSDL\"")


    #_________________________________________________________________________
    def update(self, extAttCertList=None, **xmlTags):
        """Override base class implementation to include extra code
        to allow setting of extAttCertList tag"""

        def setAttCert(attCert=None):
            if isinstance(attCert, basestring):
                return AttCertParse(attCert)
            
            elif isinstance(attCert, AttCert):
                return attCert
            
            elif attCert is not None:
                raise TypeError(\
                    "extAttCertList must contain string or AttCert types")

        if extAttCertList is not None:
            if isinstance(extAttCertList, list):
                 
                # Join into single string and filter out XML headers as  
                # ElementTree doesn't like these nested into a doc                        
                extAttCertList = map(setAttCert, extAttCertList)
            
            elif extAttCertList == '':
                extAttCertList = []
            else:
                raise TypeError("\"extAttCertList\" must be of list type")
                
        # Call super class update with revised attribute certificate list
        super(self.__class__, self).update(extAttCertList=extAttCertList,
                                           **xmlTags)


    #_________________________________________________________________________
    def updateXML(self, **xmlTags):
        """Override base class implementation to include extra code
        to include extAttCertList tag"""
        
        # Update dictionary
        self.update(**xmlTags)

        # Create XML formatted string ready for encryption
        try:
            xmlTxt = self.xmlHdr + os.linesep + \
                "<" + self.__class__.__name__ + ">" + os.linesep
                
            for tag, val in self.items():
                if isinstance(val, list):
                    # List of Attribute Certificates from other trusted hosts
                    #
                    # Call AttCert parse and return as Element type to append
                    # as branches
                    text = os.linesep.join([ac.asString(stripXMLhdr=True) \
                                            for ac in val]) 
                
                elif isinstance(val, bool):
                    text = "%d" % val
                    
                elif val is None:
                    # Leave out altogether if set to None
                    continue
                else:        
                    text = val

                xmlTxt += "    <%s>%s</%s>%s" % (tag, text, tag, os.linesep)
                
            xmlTxt += "</" + self.__class__.__name__ + ">" + os.linesep   
            self.xmlTxt = xmlTxt

        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to convert boolean"""
        
        super(self.__class__, self).parseXML()
        
        if 'mapFromTrustedHosts' in self:
            self['mapFromTrustedHosts']=bool(int(self['mapFromTrustedHosts']))
            
        if 'rtnExtAttCertList' in self:  
            self['rtnExtAttCertList'] = bool(int(self['rtnExtAttCertList']))

        # Nb. ElementTree parses attCert XML, it adds 'ns0' namespaces to all
        # the digital signatue elements - this invalidates the signature (!)
        # 
        # Fudge: re-read in using regular expressions
                    
        if 'extAttCertList' in self:
            if self['extAttCertList'] == '':
                self['extAttCertList'] = []
                return
            
            try:                
                # Find <extAttCertList>...</extAttCertList>
                extACListTxt = \
                    self.__class__.__extACListPat.findall(self.xmlTxt)[0] 
                
                # Split list and convert into AttCert objects              
                self['extAttCertList'] = \
                    [AttCertParse(acMat.group()) \
                     for acMat in \
                     self.__class__.__attCertPat.finditer(extACListTxt)]
                
            except Exception, e:
                raise AuthorisationRespError(\
                        "Error parsing Attribute Certificate List: " + str(e))


#_____________________________________________________________________________
class AuthorisationRespError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS connect response class."""
    pass


#_____________________________________________________________________________
class AuthorisationResp(XMLMsg):
    """For client to Session Manager WS connect(): formats authorisation
    response from SessionMgr.
    
    For client, enables decryption of response"""
    
    # Override base class class variables
    xmlTagTmpl = {  "attCert":           "",
                    "extAttCertList":    "",
                    "statCode":          "",
                    "errMsg":            ""    }

    accessGranted = 'AccessGranted'    
    accessDenied = 'AccessDenied'
    accessError = 'AccessError'
    
    # Regular expressions for parsing AttCerts from XML
    __attCertPat = re.compile(\
                    '<attributeCertificate>.*?</attributeCertificate>', re.S)
                    
    __extACListPat = re.compile('<extAttCertList>.*</extAttCertList>', re.S)
    __acPat = re.compile('<attCert>.*?</attCert>', re.S)


    def __init__(self, **xmlMsgKeys):
        """XML for receiving output from Session Manager authorisation call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'errMsg' or 'statCode' 
                       must be set.
        """        
        
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
                               
        # Check for valid output credentials
        if 'statCode' not in self:            

            # XML tags input as keywords expected - check minimum 
            # required are present for SessionMgr connect response
            raise AuthorisationRespError(\
                "Authorisation response must contain \"statCode\" keyword")


    #_________________________________________________________________________
    def update(self, attCert=None, extAttCertList=None, **xmlTags):
        """Override base class implementation to include extra code
        to allow setting of extAttCertList tag"""

        def setAttCert(attCert=None):
            if isinstance(attCert, basestring):
                return AttCertParse(attCert)
            
            elif isinstance(attCert, AttCert):
                return attCert
            
            elif attCert is not None:
                raise TypeError(\
                    "extAttCertList must contain string or AttCert types")

        if extAttCertList is not None:
            if isinstance(extAttCertList, list):
                 
                # Join into single string and filter out XML headers as  
                # ElementTree doesn't like these nested into a doc                        
                extAttCertList = map(setAttCert, extAttCertList)
            
            elif extAttCertList == '':
                extAttCertList = []
            else:
                raise TypeError("\"extAttCertList\" must be of list type")
                
        # Call super class update with revised attribute certificate list
        super(self.__class__, self).update(attCert=setAttCert(attCert),
                                           extAttCertList=extAttCertList,
                                           **xmlTags)


    #_________________________________________________________________________
    def updateXML(self, **xmlTags):
        """Override base class implementation to include extra code
        to include extAttCertList tag"""
        
        # Update dictionary
        self.update(**xmlTags)
        
        # Create XML formatted string ready for encryption
        try:
            xmlTxt = self.xmlHdr + os.linesep + \
                "<" + self.__class__.__name__ + ">" + os.linesep
                
            for tag, val in self.items():
                if isinstance(val, AttCert):
                    # Attribute Certificate received from Attribute Authority
                    #
                    # Remove any XML header -
                    # update() call will have converted val to AttCert type
                    text = val.asString(stripXMLhdr=True)
                  
                elif isinstance(val, list):
                    # List of Attribute Certificates from other trusted hosts
                    #
                    # Call AttCert parse and return as Element type to append
                    # as branches
                    text = os.linesep.join([ac.asString(stripXMLhdr=True) \
                                            for ac in val]) 
                
                elif isinstance(val, bool):
                    text = "%d" % val
                    
                elif val is None:
                    # Leave out altogether if set to None
                    continue
                else:        
                    text = val

                xmlTxt += "    <%s>%s</%s>%s" % (tag, text, tag, os.linesep)
                
            xmlTxt += "</" + self.__class__.__name__ + ">" + os.linesep   
            self.xmlTxt = xmlTxt

        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to parse extAttCertList tag"""
        
        super(self.__class__, self).parseXML()

        # Nb. ElementTree parses attCert XML, it adds 'ns0' namespaces to all
        # the digital signatue elements - this invalidates the signature (!)
        # 
        # Fudge: re-read in using regular expressions
                    
        if 'extAttCertList' in self:
            if self['extAttCertList'] == '':
                self['extAttCertList'] = []
                return
            
            try:                
                # Find <extAttCertList>...</extAttCertList>
                extACListTxt = \
                    self.__class__.__extACListPat.findall(self.xmlTxt)[0] 
                
                # Split list and convert into AttCert objects              
                self['extAttCertList'] = \
                    [AttCertParse(acMat.group()) \
                     for acMat in \
                     self.__class__.__attCertPat.finditer(extACListTxt)]
                
            except Exception, e:
                raise AuthorisationRespError(\
                        "Error parsing Attribute Certificate List: " + str(e))
                                          
        # Check for 'attCert' set - if so reset as a single string and convert
        # to AttCert type.  
        if 'attCert' in self and self['attCert']:
            try:
                acTxt = self.__class__.__acPat.findall(self.xmlTxt)[0]
                
                self['attCert'] = \
                AttCertParse(self.__class__.__attCertPat.findall(acTxt)[0])
                
            except Exception, e:
                raise AuthorisationRespError(\
                    "Error parsing Attribute Certificate: " + str(e))  
 

#_____________________________________________________________________________
class PubKeyReqError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS getPubKey request class."""
    pass


#_____________________________________________________________________________
class PubKeyReq(XMLMsg):
    """For client to Session Manager WS getPubKey(): formats inputs for 
    request into XML"""    
    pass


#_____________________________________________________________________________
class PubKeyRespError(XMLMsgError):    
    """Exception handling for NDG SessionMgr WS getPubKey response class."""
    pass


#_____________________________________________________________________________
class PubKeyResp(XMLMsg):
    """For client to Session Manager WS getPubKey(): formats getPubKey 
    response from SessionMgr"""
    
    # Override base class class variables
    xmlTagTmpl = {"pubKey": "", "errMsg": ""}
                        

    def __init__(self, **xmlMsgKeys):
        """XML for receiving credentials from Session Manager getPubKey call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'proxyCert' or 'sessCookie' 
                       must be set.                        
        """        
        
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
                               
        # Check for valid output credentials
        # XML tags input as keywords expected - check minimum 
        # required are present for SessionMgr getPubKey response
        if 'pubKey' not in self and 'errMsg' not in self:            
            raise PubKeyRespError(\
                "PubKey response document must contain: \"pubKey\"" + \
                " or \"errMsg\" keywords")
    