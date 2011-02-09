"""Class for digitally signed Certificate Request to NDG SimpleCA

NERC Data Grid Project

P J Kershaw 08/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

cvsID = '$Id$'

import os

# XML signature module based on xmlsec and libxml2
from xmlSigDoc import *

# XML Parsing
import cElementTree as ElementTree




#_____________________________________________________________________________
class CertReqError(Exception):
    
    """Exception handling for NDG Certificate Request class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg



        
#_____________________________________________________________________________
class CertReq(xmlSigDoc):

    """NDG Certificate Request."""

    # Certificate Request file tag
    __certReqTag = "certificateRequest"


    # Nb. pass xmlSigDoc keyword arguments in xmlSigDocArgs dictionary
    def __init__(self, filePath=None, **xmlSigDocArgs):

        """Initialisation - Certificate Request file path may be specified.
        """

        # Base class initialisation
        xmlSigDoc.__init__(self, **xmlSigDocArgs)


        if filePath is not None:
            if not isinstance(filePath, basestring):            
                raise CertReqError("Input file path must be a valid string")

            self.setFilePath(filePath)

        self.sCertReq = ''

        


    def parse(self, xmlTxt):

        """Parse an XML Certificate Request content contained in string input

        xmlTxt:     Certificate Request XML content as string"""
        
        rootElem = ElementTree.XML(xmlTxt)

        # Call generic ElementTree parser
        self.__parse(rootElem)


        # Call base class parser method to initialise libxml2 objects for
        # signature validation
        try:
            xmlSigDoc.parse(self, xmlTxt)

        except xmlSigDocError, xmlSigDocErr:
            raise CertReqError(str(xmlSigDocErr))



        
    def read(self, filePath=None):

        """Read XML Certificate Request

        filePath:   file to be read, if omitted __filePath member variable is
                    used instead"""

        if filePath:
            if not isinstance(filePath, basestring):
                raise CertReqError("Input file path must be a string.")

            self.setFilePath(filePath)
        else:
            filePath = self.getFilePath()


        try:    
            tree = ElementTree.parse(filePath)
            rootElem = tree.getroot()
        except Exception, e:
            raise CertReqError("Certificate Request: " + str(e))
        
        # Call generic ElementTree parser
        self.__parse(rootElem)


        # Call base class read method to initialise libxml2 objects for
        # signature validation
        try:
            xmlSigDoc.read(self)

        except xmlSigDocError, xmlSigDocErr:
            raise CertReqError(str(xmlSigDocErr))



        
    def __parse(self, certReqElem):

        """Private XML parsing method accepts a ElementTree.Element type
        as input

        certReqElem:       ElementTree.Element type
        """
        self.sCertReq = certReqElem.text.strip()




    def createXML(self):

        """Create XML for Certificate Request ready for signing

        Implementation of virtual method defined in xmlSigDoc base class"""

        # Nb. this method is called by CertReq.read()
 
        
        # Create string of all XML content        
        xmlTxt = "<certificateRequest>" + os.linesep + "    " + \
                 self.sCertReq + os.linesep + "</certificateRequest>"


        # Return XML file content as a string
        return xmlTxt




#_____________________________________________________________________________
# Alternative CertReq constructors
#
def CertReqRead(**certReqKeys):
    """Create a new Certificate Request read in from a file"""
    
    certReq = CertReq(**certReqKeys)
    certReq.read()
    
    return certReq




def CertReqParse(CertReqTxt, **certReqKeys):
    """Create a new Certificate Request from string content"""
    
    certReq = CertReq(**certReqKeys)
    certReq.parse(CertReqTxt)
    
    return certReq


def CertReqTest(certFilePathList):
    
    import pdb
    pdb.set_trace()


    
    certReqXMLtxt = \
"""<?xml version="1.0" encoding="UTF-8"?>
<certificateRequest>
    -----BEGIN CERTIFICATE REQUEST-----
MIIB5jCCAU8CAQAwdDEMMAoGA1UEChMDTkRHMQ0wCwYDVQQLEwRCQURDMScwJQYD
VQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMucmwuYWMudWsxFjAUBgNVBAsTDWJh
ZGMucmwuYWMudWsxFDASBgNVBAMTC1dpbGVFQ295b3RlMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDRoHov9c5mlqGdH47+dgNjfI3P00JzDNBYqxsLzYmGWDRr
NfRPtxeIW2/rtQ9xGu+bkE7IS42zi0LulfnkaAQP/ZlaY8ku6hwBI+ucMWGkQSim
BekogREHZRQHlP6EME71K8kfsgfl54WmR3WBIpD7qngc9JSQOjy0R7X5P0r2YQID
AQABoDIwMAYJKoZIhvcNAQkOMSMwITARBglghkgBhvhCAQEEBAMCBPAwDAYDVR0T
AQH/BAIwADANBgkqhkiG9w0BAQQFAAOBgQA+ngB77zhOaRJkGXKO0YupqQfDbzdR
fHJAnpSYmtLdVB3nsddCEF+iSdw9R1SX3uB1Z2bR5Xe66BancxOSfJqw7PgKGG7Z
QMQdPShfFI4dnP7lv+nqDklx5k8hWm0bhJX60PsnJysRMtmbOjfOnEAZbYODFjH8
Xp2Lxud4oYtaAQ==
-----END CERTIFICATE REQUEST-----
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>JWUPJP1h9/nMUgo62hUeTsuCjXk=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>Q4S1ASyeo2vJpYJELN6X2IEQceNxNCMN5QxdlbKeI4Nnaz1dtnVUxXeVilKuZ7ib
mbRbinxwKbdpH3XT1w5ZEGzibDJnrbkLI7+0wy/ZXtF6RzRuB04Tf8frgJSkDHy0
SyHT3DSqdXjw4zmnJ/bIStRHxHRUD+fJMW0YXI4Yf/A=</SignatureValue>
<KeyInfo>
<X509Data>
<X509Certificate>MIICWzCCAcSgAwIBAgIBCjANBgkqhkiG9w0BAQQFADBhMQwwCgYDVQQKEwNOREcx
DTALBgNVBAsTBEJBREMxJzAlBgNVBAsUHm5kZ3B1cnNlY2FAZm9laG4uYmFkYy5y
bC5hYy51azEZMBcGA1UEAxMQR2xvYnVzIFNpbXBsZSBDQTAeFw0wNTA2MTQxNjE5
MzBaFw0wNjA2MTQxNjE5MzBaMG8xDDAKBgNVBAoTA05ERzENMAsGA1UECxMEQkFE
QzEiMCAGA1UECxMZRHVtbXkgQXR0cmlidXRlIEF1dGhvcml0eTEOMAwGA1UECxMF
ZHVtbXkxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcN
AQEBBQADgY0AMIGJAoGBALwDD4NE5YLQMKIUKhg/Di/wQHzibHjQmbZg6zZrusEK
WFLFrRawjs+fa9gacu5VG7tGucY0eIy7dizHPOR1M1k/otUXolrNHcmrAlJR/mRM
DDx9kCkf9kraDzUxVEwkPhKVHip7CGskti3b+2vpDnAQaZ/7CoJ2BaOqbiolkONN
AgMBAAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQA5
5naF0Y8SUxoZ65Skvfgj2tTofYxC0WSQbIPbwcyrEOVurThYUT05DiulI+jajvf8
L9R6pgMrfzJbChpgSI2Qvh8nsZ92CZo5Ot2ac8zCUIMgcr1VRvGG+BE8sFmy4uFW
ngNrNFNYuP1gTDfG6oKPkrFXWDV9v15IMe1iCo7bVg==</X509Certificate>
</X509Data>
</KeyInfo>
</Signature></certificateRequest>"""

    try:
        certReq = CertReqParse(certReqXMLtxt,
                               certFilePathList=certFilePathList)

        print certReq.isValidSig()
        
    except Exception, e:
        print str(e)
