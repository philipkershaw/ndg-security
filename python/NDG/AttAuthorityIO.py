"""NDG Attribute Authority Web Services helper classes for I/O between client
and server

NERC Data Grid Project

P J Kershaw 14/12/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'
        
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
                    "clntCert":     ""    }
                    
    xmlMandTags = ["proxyCert"]


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

        if credential is not None:
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
                
            for tag, val in xmlTags.items():
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
        to parse extAttCertList tag"""
        
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
class GetTrustedHostInfoReqError(XMLMsgError):    
    """Exception handling for NDG AttAuthority WS GetTrustedHostInfo request 
    class."""
    pass


#_____________________________________________________________________________
class GetTrustedHostInfoReq(XMLMsg):
    """For client to Attribute Authority WS GetTrustedHostInfo(): formats 
    inputs for request into XML and encrypts.
    
    Attribute Authority enables decryption of result"""
    
    # Override base class class variables
    xmlTagTmpl = {  "role":    ""}
                    
    xmlMandTags = ["role"]


#_____________________________________________________________________________
class GetTrustedHostInfoRespError(XMLMsgError):    
    """Exception handling for NDG AttAuthority WS GetTrustedHostInfo response 
    class."""
    pass


#_____________________________________________________________________________
class GetTrustedHostInfoResp(XMLMsg):                              
    """For client to Attribute Authority WS getTrustedInfo(): formats 
    response from AttAuthority.
    
    For client, enables decryption of response"""
    
    # Override base class class variables
    xmlTagTmpl = {"trustedHostInfo": "", "errMsg": ""}

    xmlMandTags = ["errMsg"]


    def __init__(self, **xmlMsgKeys):
        """XML for receiving output from Attribute Authority authorisation 
        call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'errMsg' or 'statCode' 
                       must be set.
        """        
        
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
