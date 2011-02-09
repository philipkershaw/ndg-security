"""NDG Web Services helper class for XML I/O between WS client and server

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

# For XML parsing
import cElementTree as ElementTree

from XMLSecDoc import *


#_____________________________________________________________________________
class XMLMsgError(Exception):    
    """Exception handling for NDG WS I/O Message class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class XMLMsg(dict):
    """Super class for encrypting arguments in SOAP messages for NDG Security
    Web services"""
    
    # Derived classes should specify XML tags and values as keywords and
    # values in a dictionary
    xmlTagTmpl = {}

    # Set Mandatory tags - if any of these are not present raise an exception
    xmlMandTags = []
    
    def __init__(self, 
                 encrXMLtxt=None,
                 xmlTxt=None,
                 encrPubKeyFilePath=None,
                 encrPriKeyFilePath=None,
                 encrPriKeyPwd=None,
                 xmlVers="1.0",
                 xmlEncoding="UTF-8",
                 **xmlTags):
        """XML for sending/receiving encrypted XML arguments with NDG web
        services
        
        To encrypt message to send:
            encrXML = XMLMsg(encrPubKeyFilePath=filePath,
                             [xmlTxt]|[Key1=key1, Key2=key2, ...])
                              
        For recipient to decrypt:
            encrXML = XMLMsg(encrPriKeyFilePath=filePath,
                             encrPriKeyPwd=pwd,
                             encrXMLtxt=xmlTxt)
                              
        encrXMLtxt:            string containing encrypted text for 
                               decryption
        encrPubKeyFilePath:    public key to encrypt message - use when 
                               sending a message only
        encrPriKeyFilePath:    private key used to decrypt message - use 
                               when receiving a message only
        encrPriKeyPwd:         password for private key
        
        xmlVers:               version number in standard XML header
        xmlEncoding:           encoding type set in XML header
        **xmlTags:             keywords corresponding to the XML tags to be 
                               encrypted
        """
        
        self.__xmlTags = {}
        self.__encrXMLtxt = encrXMLtxt
        self.__xmlTxt = xmlTxt
        
        self.__xmlHdr = "<?xml version=\"%s\" encoding=\"%s\"?>" % \
                        (xmlVers, xmlEncoding)
        
        # Allow user credentials to be access like dictionary keys
        dict.__init__(self)
        
        
        # Initialisation for XML Security class used for encryption
        try:
            self.__xmlSecDoc=XMLSecDoc(encrPriKeyFilePath=encrPriKeyFilePath,
                                       encrPubKeyFilePath=encrPubKeyFilePath)
        except Exception, e:
            raise XMLMsgError("Error initialising XML security: %s" % e)     
 
                 
        # Check mode:
        # - encrypted XML entered for decryption
        # or 
        # - XML or XML tags entered as keywords to make XML document for
        # encryption
        if encrXMLtxt:            
            # Encrypted text has been input for decryption
            if not encrPriKeyFilePath:
                raise XMLMsgError(\
                    "A private key must be set in order to decrypt the data")
            
            try:
                self.__xmlSecDoc.decrypt(xmlTxt=encrXMLtxt,
                                         encrPriKeyPwd=encrPriKeyPwd)
                                          
                self.__xmlTxt = str(self.__xmlSecDoc)
                           
            except Exception, e:
                raise XMLMsgError("Error decrypting credentials: %s" % e)     

            # Parse elements from decrypted result saving as dictionary
            # self.__xmlTags
            self.parseXML()
        else:
            # XML text or XML tags input ready for encryption
            if xmlTxt:
                # Input XML text set - parse tags into dictionary self.__xmlTags
                self.parseXML()                
            else:
                # XML text will be set from tags set as keywords
                self.updateXML(**xmlTags)
                
            if encrPubKeyFilePath:
                try:
                    self.__xmlSecDoc.encrypt(xmlTxt=self.__xmlTxt)
                    self.__encrXMLtxt = str(self.__xmlSecDoc)
                    
                except Exception, e:
                    raise XMLMsgError("Error encrypting credentials: %s" % e)

        # Check for any mandatory tags that have not been set
        missingTags = [tag for tag in self.xmlMandTags if not tag in self]
        if missingTags:
            raise XMLMsgError(\
                'The following tag(s) must be set: "%s"' % \
                                                    '", "'.join(missingTags))
                
                
    def __repr__(self):
        """Print the XML for user credentials"""
        return repr(self.__xmlTags)
            
            
    def __str__(self):
        """Print the XML for user credentials"""
        return self.__xmlTxt
            

    def __call__(self):
        """Return text for output - encrypted version if set otherwise plain
        text"""
        return self.__encrXMLtxt or self.__xmlTxt
        

    def __getXMLhdr(self):
        return self.__xmlHdr
    
    xmlHdr = property(fget=__getXMLhdr,
                      doc="Standard header line for XML document")
                      
    def __getXMLtxt(self):
        """Get the user credentials as XML formatted string"""
        return self.__xmlTxt

    def __setXMLtxt(self, xmlTxt):
        """Allow text to be set if class of calling method is XMLMsg 
        derived"""
        
        try:
            # Get previous frame from stack
            frame = sys._getframe().f_back
        except Exception, e:
            raise AttributeError("Error checking calling method")
        
        try:
            # Check the class that the calling method belongs to
            callerClassName = frame.f_locals['self'].__class__.__name__
    
            if callerClassName == self.__class__.__name__:
                self.__xmlTxt = xmlTxt
                return
            else:
                # Raise KeyError so that execution moves to except block
                raise KeyError
            
        except KeyError:
            # self variable may not be present
            AttributeError("Caller must be a method of a %s derived class" % \
                           self.__class__.__name__)

        
    # Read-only property
    xmlTxt = property(fget=__getXMLtxt,
                      fset=__setXMLtxt,
                      doc="XML string text for message")                      

    
    def __getEncrXMLtxt(self):
        """Get the user credentials as encrypted XML formatted string"""
        return self.__encrXMLtxt
    
    # Read-only property
    encrXMLtxt = property(fget=__getEncrXMLtxt,
                          doc="encrypted XML user credentials")                      

                          
    def __delitem__(self, key):
        "keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from ' + \
                       self.__class__.__name__)


    def __getitem__(self, key):
        """Access user credentials as dictionary keys"""
        
        # Check input key
        if self.__xmlTags.has_key(key):
            # key recognised
            return self.__xmlTags[key]                
        else:
            # key not recognised 
            raise KeyError('Key "%s" not recognised for %s' % \
                           (key, self.__class__.__name__))


    def __setitem__(self, key, item):
        """Allows keys to be set methods of *derived* classes only
        
        - simulates behaviour like 'protected' data members in C++"""
        
        if not key in self.__xmlTags:
            raise KeyError("Key \"%s\" invalid for %s" % \
                            (key, self.__class__.__name__))
                            
        try:
            # Get previous frame from stack
            frame = sys._getframe().f_back
        except Exception, e:
            raise keyError("Error checking caller")
        
        try:
            # Check the class that the calling method belongs to
            callerClassName = frame.f_locals['self'].__class__.__name__
    
            if callerClassName == self.__class__.__name__:
                self.__xmlTags[key] = item
                return
            
        except KeyError:
            # self variable may not be present
            pass
              
        raise KeyError('Keys may only be set by methods of derived classes')


    # 'in' operator
    def __contains__(self, key):
        return key in self.__xmlTags
  
    def has_key(self, key):
        return self.__xmlTags.has_key(key)      

    def clear(self):
        raise KeyError("Data cannot be cleared from " + \
                       self.__class__.__name__)
   
    def copy(self):
        import copy
        return copy.copy(self)
    
    def keys(self):
        return self.__xmlTags.keys()

    def items(self):
        return self.__xmlTags.items()

    def values(self):
        return self.__xmlTags.values()


    def update(self, xmlTagsDict=None, **xmlTags):
        """override dict.update to carry out validation
        
        Nb. unlike dict.update, an iterable can't be passed in"""
        
        if xmlTagsDict:
            if not isinstance(xmlTagsDict, dict):
                raise TypeError("Input must be dict type")
            
            # Dictionary input overrides keywords
            xmlTags = xmlTagsDict
           
        if not len(xmlTags):
            return          
              
        # Check keys are valid - xmlTagTmpl MUST have been altered from the 
        # default otherwise this test will always fail
        unknownKeys = [key for key in xmlTags if key not in self.xmlTagTmpl]
        if unknownKeys:
            raise KeyError(\
                "Invalid keywords set for update: \"%s\"" % \
                '", "'.join(unknownKeys))
                
        # Copy keywords - but only those that are NOT None
        self.__xmlTags.update(\
                dict([(k, v) for k, v in xmlTags.items() if v is not None]))


    def updateXML(self, **xmlTags):
        """Build XML message string from keywords corresponding to
        tags input 
        
        Override in a derived class if required"""
        
        # Update dictionary
        self.update(**xmlTags)
        
        # Create XML formatted string ready for encryption
        try:
            rootNode = ElementTree.Element(self.__class__.__name__)
            rootNode.tail = os.linesep
            
            for tag in self.__xmlTags:
                # ElementTree tostring doesn't like bool types
                elem = ElementTree.SubElement(rootNode, tag)
                elem.tail = os.linesep
                
                if isinstance(self.__xmlTags[tag], bool):                    
                    elem.text = "%d" % self.__xmlTags[tag]
                else:
                    elem.text = self.__xmlTags[tag]
                    
                     
            self.__xmlTxt = self.__xmlHdr + os.linesep + \
                                                ElementTree.tostring(rootNode)
        except Exception, e:
            raise XMLMsgError("Creating XML: %s" % e)


    def parseXML(self, rtnRootElem=False):
        """Parse unencrypted XML in self.__xmlTxt
        
        Assumes single level of nesting of XML tags - override in a derived 
        class if required
        
        rtnRootElem:    set to True to return the root element - useful for 
                        derived classes to be able to access"""
        
        # Convert strings containing digits to integer type
        intCast = lambda s: int(str(s).isdigit()) and int(s) or s
        
        try:
            rootElem = ElementTree.XML(self.__xmlTxt)
            
            xmlTags = {}
            for elem in rootElem:
                text = intCast(elem.text)
                if text is None:
                    xmlTags[elem.tag] = os.linesep.join(\
                        [ElementTree.tostring(subElem) for subElem in elem])
                else:
                    xmlTags[elem.tag] = elem.text
                            
            self.__xmlTags = xmlTags
            
        except Exception, e:
            raise XMLMsgError("Error parsing XML text: %s" % e)     

        return rootElem
    
