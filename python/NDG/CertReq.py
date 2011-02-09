"""Class for digitally signed Certificate Request to NDG SimpleCA

NERC Data Grid Project

P J Kershaw 08/08/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

reposID = '$Id$'

import os

# XML signature module based on xmlsec and libxml2
from XMLSecDoc import *

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
class CertReq(XMLSecDoc):
    """NDG Certificate Request document to send to Simple CA."""

    # Certificate Request file tag
    __certReqTag = "certificateRequest"


    # Nb. pass XMLSecDoc keyword arguments in xmlSecDocArgs dictionary
    def __init__(self, filePath=None, **xmlSecDocArgs):

        """Initialisation - Certificate Request file path may be specified.
        """

        # Base class initialisation
        XMLSecDoc.__init__(self, **xmlSecDocArgs)


        if filePath is not None:
            if not isinstance(filePath, basestring):            
                raise CertReqError("Input file path must be a valid string")

            self.filePath = filePath

        self.__certReqTxt = ''

        
    #_________________________________________________________________________
    def __getCertReqTxt(self):
        """Get text content of certificate request"""
        return self.__certReqTxt


    def __setCertReqTxt(self, certReqTxt):
        """Set text content of certificate request"""
        
        if not isinstance(certReqTxt, basestring):
            raise AttributeError("Setting certificate request text: " + \
                                 "input must be a valid string")
                               
        self.__certReqTxt = certReqTxt


    def __delCertReqTxt(self):
        """Prevent certificate request text from being deleted."""
        raise AttributeError("\"certReqTxt\" attribute cannot be deleted")


    # Publish attribute as read/write
    certReqTxt = property(fget=__getCertReqTxt,
                          fset=__setCertReqTxt,
                          fdel=__delCertReqTxt,
                          doc="Text for certificate request")


    #_________________________________________________________________________
    def parse(self, xmlTxt):
        """Parse an XML Certificate Request content contained in string input

        xmlTxt:     Certificate Request XML content as string"""
        
        rootElem = ElementTree.XML(xmlTxt)

        # Call generic ElementTree parser
        self.__parse(rootElem)


        # Call base class parser method to initialise libxml2 objects for
        # signature validation
        try:
            XMLSecDoc.parse(self, xmlTxt)

        except Exception, e:
            raise CertReqError("Certificate Request: %s" % e)


    #_________________________________________________________________________       
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
            XMLSecDoc.read(self)

        except Exception, e:
            raise CertReqError("Certificate Request: %s" % e)

        
    #_________________________________________________________________________
    def __parse(self, certReqElem):
        """Private XML parsing method accepts a ElementTree.Element type
        as input

        certReqElem:       ElementTree.Element type
        """
        self.__certReqTxt = certReqElem.text.strip()


    #_________________________________________________________________________
    def createXML(self):
        """Create XML for Certificate Request ready for signing

        Implementation of virtual method defined in XMLSecDoc base class"""

        # Nb. this method is called by CertReq.read()
 
        
        # Create string of all XML content        
        xmlTxt = "<certificateRequest>" + os.linesep + "    " + \
                 self.__certReqTxt + os.linesep + "</certificateRequest>"


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


#_____________________________________________________________________________
def CertReqParse(certReqTxt, **certReqKeys):
    """Create a new Certificate Request from string content"""
    
    certReq = CertReq(**certReqKeys)
    certReq.parse(certReqTxt)
    
    return certReq


#_____________________________________________________________________________
def CertReqTest(certFilePathList):
    
    import pdb
    pdb.set_trace()
   
    certReqXMLtxt = \
"""<?xml version="1.0" encoding="UTF-8"?>
<certificateRequest></certificateRequest>"""

    try:
        certReq = CertReqParse(certReqXMLtxt,
                               certFilePathList=certFilePathList)

        print certReq.isValidSig()
        
    except Exception, e:
        print str(e)
