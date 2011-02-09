"""NDG Attribute Authority Web Services helper classes for I/O between client
and server

NERC Data Grid Project

P J Kershaw 14/12/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

reposID = '$Id$'
        
from XMLMsg import *

# For use with AuthorisationResp class
from AttCert import *

#_____________________________________________________________________________
class AuthorisationReqError(XMLMsgError):    
    """Exception handling for NDG AttAuthority WS authorisation request class.
    """
    pass


#_____________________________________________________________________________
class AuthorisationReq(XMLMsg):
    """For client to Attribute Authority WS reqAuthorisation(): formats inputs
    for request into XML and encrypts.
    
    Attribute Authority enables decryption of result"""
    
    # Override base class class variables
    xmlTagTmpl = {  "proxyCert":    "",
                    "userAttCert":  "",
                    "encrCert":     ""    }
                    
    xmlMandTags = ["proxyCert"]
                                
                                
    #_________________________________________________________________________
    def update(self, userAttCert=None, **xmlTags):
        """Override base class implementation to include extra code
        to allow setting of userAttCert tag"""

        if userAttCert:
            if isinstance(userAttCert, basestring):
                attCert = AttCertParse(userAttCert)
            
            elif isinstance(userAttCert, AttCert):
                attCert = userAttCert
            else:
                raise TypeError(\
                    "userAttCert keyword must contain string or AttCert type")
                        
        else:
            attCert = None
                
        # Call super class update with revised attribute certificate list
        super(self.__class__, self).update(userAttCert=attCert, **xmlTags)
                                           
                                           
    #_________________________________________________________________________
    def updateXML(self, **xmlTags):
        """Override base class implementation to include extra code
        to allow attribute certificate to be set from a string or AttCert
        type"""
        
        # Update dictionary
        self.update(**xmlTags)
        
        # Create XML formatted string ready for encryption
        try:
            xmlTxt = self.xmlHdr + os.linesep + \
                "<" + self.__class__.__name__ + ">" + os.linesep
                
            for tag, val in self.items():
                if tag == "userAttCert":
                    # Remove any XML header -
                    # update() call will have converted val to AttCert type
                    val = val.asString(stripXMLhdr=True)
                    
                xmlTxt += "    <%s>%s</%s>%s" % (tag, val, tag, os.linesep)
                    
            xmlTxt += "</" + self.__class__.__name__ + ">" + os.linesep   
            self.xmlTxt = xmlTxt
            
        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to parse userAttCert tag - if left with the default, elementtree
        adds extra "ns0" namespaces which invalidate the signature(!)"""
        
        rootElem = super(self.__class__, self).parseXML(rtnRootElem=True)
        if 'userAttCert' in self:

            # Convert attribute certificate to AttCert instance
            try:
                attCertPat = re.compile(\
                    '<attributeCertificate>.*</attributeCertificate>', re.S)
                attCertTxt = attCertPat.findall(self.xmlTxt)[0]
                
                self['userAttCert'] = AttCertParse(attCertTxt)
                
            except Exception, e:
                raise AuthorisationRespError(\
                    "Error parsing Attribute Certificate: " + str(e))  


#_____________________________________________________________________________
class AuthorisationRespError(XMLMsgError):    
    """Exception handling for NDG AttAuthority WS connect response class."""
    pass


#_____________________________________________________________________________
class AuthorisationResp(XMLMsg):
    """For client to Attribute Authority WS reqAuthorisation(): formats 
    authorisation response from AttAuthority.
    
    For client, enables decryption of response"""
    
    # Override base class class variables
    xmlTagTmpl = {  "credential":        "",
                    "statCode":          "",
                    "errMsg":            ""    }

    xmlMandTags = ["statCode"]
    
    accessGranted = 'AccessGranted'    
    accessDenied = 'AccessDenied'
    accessError = 'AccessError'


    def __init__(self, **xmlMsgKeys):
        """XML for receiving output from Attribute Authority authorisation 
        call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'errMsg' or 'statCode' 
                       must be set.
        """        
        
        # Allow credentials to be accessed like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
        if 'credential' not in self and 'errMsg' not in self:
            raise AuthorisationRespError(\
                                'Expecting "credential" or "errMsg" keywords')
                                
                                
    #_________________________________________________________________________
    def update(self, credential=None, **xmlTags):
        """Override base class implementation to include extra code
        to allow setting of extAttCertList tag"""

        if credential:
            if isinstance(credential, basestring):
                attCert = AttCertParse(credential)
            
            elif isinstance(credential, AttCert):
                attCert = credential
            else:
                raise TypeError(\
                    "credential keyword must contain string or AttCert type")
                        
        else:
            attCert = None
                
        # Call super class update with revised attribute certificate list
        super(self.__class__, self).update(credential=attCert, **xmlTags)
                                           
                                           
    #_________________________________________________________________________
    def updateXML(self, **xmlTags):
        """Override base class implementation to include extra code
        to allow attribute certificate to be set from a string or AttCert
        type"""
        
        # Update dictionary
        self.update(**xmlTags)
        
        # Create XML formatted string ready for encryption
        try:
            xmlTxt = self.xmlHdr + os.linesep + \
                "<" + self.__class__.__name__ + ">" + os.linesep
                
            for tag, val in self.items():
                if tag == "credential":
                    # Remove any XML header -
                    # update() call will have converted val to AttCert type
                    val = val.asString(stripXMLhdr=True)
                    
                xmlTxt += "    <%s>%s</%s>%s" % (tag, val, tag, os.linesep)
                    
            xmlTxt += "</" + self.__class__.__name__ + ">" + os.linesep   
            self.xmlTxt = xmlTxt
            
#            rootNode = ElementTree.Element(self.__class__.__name__)
#            rootNode.tail = os.linesep
#            
#            for tag in xmlTags:
#                # ElementTree tostring doesn't like bool types
#                elem = ElementTree.SubElement(rootNode, tag)
#                elem.tail = os.linesep
#                
#                if isinstance(self[tag], bool):
#                    elem.text = "%d" % self[tag]
#                
#                elif tag == 'credential':
#
#                    # str() will convert self[tag] correctly if it is an
#                    # AttCert type 
#                    attCertElem = ElementTree.XML(str(self[tag]))
#                    attCertElem.tail = os.linesep
#                    elem.append(attCertElem)
#                else:        
#                    elem.text = self[tag]
#                     
#            self.xmlTxt = self.xmlHdr + os.linesep + \
#                                                ElementTree.tostring(rootNode)
        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to parse extAttCertList tag - if left with the default, elementtree
        adds extra "ns0" namespaces which invalidate the signature(!)"""
        
        rootElem = super(self.__class__, self).parseXML(rtnRootElem=True)
        if 'credential' in self:

            # Convert attribute certificate to AttCert instance
            try:
                attCertPat = re.compile(\
                    '<attributeCertificate>.*</attributeCertificate>', re.S)
                attCertTxt = attCertPat.findall(self.xmlTxt)[0]
                
                self['credential'] = AttCertParse(attCertTxt)
                
            except Exception, e:
                raise AuthorisationRespError(\
                    "Error parsing Attribute Certificate: " + str(e))  


#_____________________________________________________________________________
class TrustedHostInfoReqError(XMLMsgError):    
    """Exception handling for NDG AttAuthority WS GetTrustedHostInfo request 
    class."""
    pass


#_____________________________________________________________________________
class TrustedHostInfoReq(XMLMsg):
    """For client to Attribute Authority WS GetTrustedHostInfo(): formats 
    inputs for request into XML and encrypts.
    
    Attribute Authority enables decryption of result"""
    
    # Override base class class variables
    xmlTagTmpl = {"role": "", "encrCert": ""}


#_____________________________________________________________________________
class TrustedHostInfoRespError(XMLMsgError):    
    """Exception handling for NDG AttAuthority WS GetTrustedHostInfo response 
    class."""
    pass


#_____________________________________________________________________________
class TrustedHostInfoResp(XMLMsg):                              
    """For client to Attribute Authority WS getTrustedInfo(): formats 
    response from AttAuthority.
    
    For client, enables decryption of response"""
    
    # Override base class class variables
    xmlTagTmpl = {"trustedHosts": "", "errMsg": ""}


    def __init__(self, **xmlMsgKeys):
        """XML for receiving output from Attribute Authority authorisation 
        call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'errMsg' or 'statCode' 
                       must be set.
        """        
        
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
        
    #_________________________________________________________________________
    def updateXML(self, **xmlTags):
        """Override base class implementation to include extra code
        to allow attribute certificate to be set from a string or AttCert
        type"""
        
        # Update dictionary
        self.update(**xmlTags)
        
        # Create XML formatted string ready for encryption
        try:
            xmlTxt = self.xmlHdr + os.linesep + \
                "<" + self.__class__.__name__ + ">" + os.linesep
                
            if "trustedHosts" in xmlTags:
                xmlTxt += "    <trustedHosts>%s" % os.linesep
                
                for host, hostInfo in xmlTags['trustedHosts'].items():
                    xmlTxt += "        <trusted name=\"%s\">" % host
                    xmlTxt += os.linesep
                    xmlTxt += "            <wsdl>%s</wsdl>" % hostInfo['wsdl']
                    xmlTxt += "            <loginURI>%s</loginURI>" % \
                                                        hostInfo['loginURI']
                    xmlTxt += os.linesep
                    xmlTxt += "            <roleSet>" + os.linesep
                    xmlTxt += ''.join(["                <role>%s</role>%s" % \
                                        (role, os.linesep) \
                                        for role in hostInfo['role']])
                    xmlTxt += "            </roleSet>" + os.linesep                    
                    xmlTxt += "        </trusted>" + os.linesep

                xmlTxt += "    </trustedHosts>%s" % os.linesep

            if "errMsg" in xmlTags:
                xmlTxt += "    <errMsg>%s</errMsg>%s" % \
                                            (xmlTags['errMsg'], os.linesep)
                    
            xmlTxt += "</" + self.__class__.__name__ + ">" + os.linesep   
            self.xmlTxt = xmlTxt
            

        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to parse trusted hosts info"""
        
        rootElem = super(self.__class__, self).parseXML(rtnRootElem=True)
        
        if 'trustedHosts' not in self:
            # Some error occured on the server such that trustedHosts wasn't 
            # set
            return
        
        self['trustedHosts'] = {}
        
        trustedHostsElem = rootElem.find('trustedHosts')
        if not trustedHostsElem:
            # No trusted hosts were found
            return
         
        for trusted in trustedHostsElem:
            try:
                host = trusted.items()[0][1]
                
                # Add key for trusted host name
                self['trustedHosts'][host] = {}
                
                # Add WSDL URI, loginURI and role set for that host
                self['trustedHosts'][host]['wsdl'] = \
                                            trusted.find('wsdl').text.strip()
                                            
                self['trustedHosts'][host]['loginURI'] = \
                                        trusted.find('loginURI').text.strip()
                                            
                self['trustedHosts'][host]['role'] = \
                    [role.text.strip() for role in trusted.find('roleSet')]
                  
            except Exception, e:
                raise TrustedHostInfoRespError(\
                "Error parsing tag \"%s\" in trusted host info response: %s" \
                % (trusted.tag, str(e)))
 

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
                