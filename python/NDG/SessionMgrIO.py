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
    xmlTagTmpl = {  "userName":          "",
                    "pPhrase":           "",
                    "proxyCert":         "",
                    "sessID":            "",
                    "webClnt":           "",
                    "encrCert":          ""    }
                        

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
                    "aaWSDL":                 "",
                    "reqRole":                "",
                    "mapFromTrustedHosts":    "",
                    "extAttCertList":         "",
                    "extTrustedHostList":     "",
                    "encrCert":               ""    }

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
        if 'sessID' not in self or \
           'encrSessMgrWSDLuri' not in self or \
           'aaWSDL' not in self:            
            raise AuthorisationReqError(\
                "Authorisation request must include: \"sessID\", " + \
                "\"encrSessMgrWSDLuri\" and \"aaWSDL\"")


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


    def __init__(self, **xmlMsgKeys):
        """XML for receiving output from Session Manager authorisation call
        
        xmlMsgKeys:    keywords for XMLMsg super-class.  If XML tags are 
                       input as keywords then 'errMsg' or 'statCode' 
                       must be set.
        """        
        
        # Allow user credentials to be access like dictionary keys
        super(self.__class__, self).__init__(**xmlMsgKeys)
        
                               
        # Check for valid output credentials
        if 'errMsg' not in self and 'statCode' not in self:            

            # XML tags input as keywords expected - check minimum 
            # required are present for SessionMgr connect response
            raise AuthorisationRespError(\
                "Authorisation response must contain: \"errMsg\"" + \
                " or \"statCode\" keywords")


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
            if not isinstance(extAttCertList, list):
                raise TypeError(\
                    "\"extAttCertList\" must be of list type")
     
     
            # Join into single string and filter out XML headers as  
            # ElementTree doesn't like these nested into a doc                        
            attCertList = map(setAttCert, extAttCertList)
        else:
            attCertList = None
                
        # Call super class update with revised attribute certificate list
        super(self.__class__, self).update(attCert=setAttCert(attCert),
                                           extAttCertList=attCertList,
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
                
            for tag in xmlTags:
                if isinstance(self[tag], AttCert):
                    # Attribute Certificate received from Attribute Authority
                    #
                    # Remove any XML header -
                    # update() call will have converted val to AttCert type
                    text = self[tag].asString(stripXMLhdr=True)
                  
                elif isinstance(self[tag], list):
                    # List of Attribute Certificates from other trusted hosts
                    #
                    # Call AttCert parse and return as Element type to append
                    # as branches
                    text = os.linesep.join([ac.asString(stripXMLhdr=True) \
                                            for ac in self[tag]]) 
                
                elif isinstance(self[tag], bool):
                    text = "%d" % self[tag]
                else:        
                    text = self[tag]

                xmlTxt += "    <%s>%s</%s>%s" % (tag, text, tag, os.linesep)
                
            xmlTxt += "</" + self.__class__.__name__ + ">" + os.linesep   
            self.xmlTxt = xmlTxt

        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    #_________________________________________________________________________
    def parseXML(self):
        """Override base class implementation to include extra code
        to parse extAttCertList tag"""
        
        rootElem = super(self.__class__, self).parseXML(rtnRootElem=True)
        
        extAttCertListElem = rootElem.find("extAttCertList")
        if extAttCertListElem:

            # Add attribute certificates as AttCert instances
            try:
                self['extAttCertList'] = \
                    [AttCertParse(ElementTree.tostring(elem)) \
                    for elem in extAttCertListElem]
                    
            except Exception, e:
                raise AuthorisationRespError(\
                    "Error parsing Ext. Attribute Certificate List: "+str(e))                                
 
                                        
#_____________________________________________________________________________    
if __name__ == "__main__":
     # Client side - Set up input for SessionMgr WSDL connect()
#    cr = ConnectReq(userName="WileECoyote", 
#                    pPhrase="ACME Road Runner catcher", 
#                    encrPubKeyFilePath="../certs/badc-aa-cert.pem")

    # Server side - decrypt connectReq from connect() request
#    cr = ConnectReq(encrXMLtxt=open("../Tests/xmlsec/connectReq.xml").read(),
#                  encrPriKeyFilePath="../certs/badc-aa-key.pem",
#                  encrPriKeyPwd="    ")

    # Server side - make a connect response message
#    cr1 = ConnectResp(sessCookie="A proxy certificate")
#
#    cr2 = ConnectResp(sessCookie="A session cookie", 
#                      encrPubKeyFilePath="../certs/badc-aa-cert.pem")
                  
#    import pdb
#    pdb.set_trace()
    
    extAttCertList = [
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 16 11 53 36</notBefore> 
        <notAfter>2005 09 16 19 53 29</notAfter> 
    </validity>
    <attributes>
        <roleSet>
                <role>
                <name>government</name>
        </role>
        </roleSet>
    </attributes>
    <provenance>original</provenance> 
    </acInfo>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>i1q2jwEDy0Sxc+ChxW9p4KCBynU=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>aXmExRkD4mZ9OdSlUcVUPIZ/r5v31Dq6IwU7Ox2/evd6maZeECVH4kGvGGez2VA5
lKhghRqgmAPsgEfZlZ3XwFxxo8tQuY6pi19OqwLV51R5klysX6fKkyK2JVoUG8Y3
7fACirNGZrZyf93X8sTvd02xN1DOTp7zt1afDsu3qGE=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>""",
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 29 15 45 49</notBefore> 
        <notAfter>2005 09 29 23 45 49</notAfter> 
    </validity>
    <attributes>
        <roleSet>
                <role>
                <name>government</name>
        </role>
        </roleSet>
    </attributes>
    <provenance>original</provenance> 
    </acInfo>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>/Kw9IbBQuQAdNYAgvp2m01l663k=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>Q7lhq/jt+m2trRPyWrZ6BQcIibXrstVS/xKTAhR4puv7kVngIm64r45MJ2GQpQan
QaVdVuOl8QPX8ila0j8sIz47FtriRWZ8fCssFYWR/7n3AKjNd22ChAshxHfZCJY4
fzJSXgEN+FN0ArOWT49FbhDVf7LEGO+MR+TP+ZKt6uY=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>""",
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 16 10 19 32</notBefore> 
        <notAfter>2005 09 16 18 19 14</notAfter> 
    </validity>
    <attributes>
        <roleSet>
                <role>
                <name>government</name>
        </role>
        </roleSet>
    </attributes>
    <provenance>original</provenance> 
    </acInfo>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>tvftcf7fevu4PQqK2PhGFVzZlFo=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>cga7gcRSeKkI8+k5HiRdfxDz0wRA741lRaI0FCZ0e7rJH3IwxEv6C3fNB0a8Slgv
R2/1b+xCHtNX0jaMLDnAv/AvtC8DfcV8yiDZOAQ/qXDkASB2OHDo6qM+Zlkf97U+
dbjIuZ6bgXa2c9OlT9PUiCcDZt6uLmiu//28ZnFy7Pw=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>"""
]

    ar1 = AuthorisationResp(extAttCertList=extAttCertList,
                            statCode=AuthorisationResp.accessDenied,
                            errMsg="User is not registered at data centre")
#    import pdb
#    pdb.set_trace()                          

    ar2 = AuthorisationResp(xmlTxt=str(ar1))
    
    # check XMLSecDoc.__del__ error
    del ar1
    del ar2
    