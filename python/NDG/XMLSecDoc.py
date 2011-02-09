"""NDG XML Security - Encryption and Digital Signature

Wraps pyXMLSec package

Nerc Data Grid Project

P J Kershaw 05/04/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

cvsID = '$Id$'


import types
import os

# Fudge for re-directing error output from xmlsec.shutdown()
import sys

# For asString() - enables XML header to be stripped if required
import re

# Use to create buffer for string output for asString() method
from cStringIO import StringIO

# xmlsec requires libxml2
import libxml2

# XML security module
import xmlsec        


class XMLSecDocError(Exception):
    """Exception handling for NDG XML Security class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg


class XMLSecDoc(object):
    """Implements XML Signature and XML Encryption for a Document."""

    #__metaclass__ = XMLSecDocMetaClass
    
    def __init__(self,
                 filePath=None,
                 signingKeyFilePath=None,
                 encrPubKeyFilePath=None,
                 encrPriKeyFilePath=None,
                 certFilePathList=None):

        """Initialisation -
            
        filePath:            file path for document
        signingKeyFilePath:  file path for private key used in signature
        encrPriKeyFilePath:     file path for private key used to decrypt
                             previously encrypted document
        certFilePathList:    list of public keys used for checking signature
                             of a document or for encrypting a document"""

        self.__filePath = None
        self.__signingKeyFilePath = None
        self.__encrPubKeyFilePath = None
        self.__encrPriKeyFilePath = None
        self.__certFilePathList = None


        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise XMLSecDocError("Input key file path is %s" % \
                                     type(filePath) + \
                                     ": string type expected")

            self.__filePath = filePath


        # Private key file to be used to sign the document
        if signingKeyFilePath is not None:
            self.__setSigningKeyFilePath(signingKeyFilePath)


        # Public key file to be used to encrypt document
        if encrPubKeyFilePath is not None:
            self.__setEncrPubKeyFilePath(encrPubKeyFilePath)


        # Private key file to be used to decrypt document
        if encrPriKeyFilePath is not None:
            self.__setEncrPriKeyFilePath(encrPriKeyFilePath)


        # This may be either of:
        # 1) Certificate file to be used for signing document
        # 2) list of files one of which is the certificate used to sign the
        # document being checked
        if certFilePathList is not None:
            self.__setCertFilePathList(certFilePathList)


        # Keep track of libxml2/libxmlsec variables which need explicit
        # freeing
        self.__libxml2Doc = None
        self.__bLibxml2DocFreed = False
            
        self.__libxml2Ctxt = None
        self.__bLibxml2CtxtFreed = False

        self.__dSigCtxt = None
        self.__bDSigCtxtFreed = False

        self.__encCtxt = None
        self.__bEncCtxtFreed = False

        self.__keysMngr = None
        self.__bKeysMngrFreed = False

        self.__keysStore = None
        self.__bKeysStoreFreed = False
 
        self.__initLibs()
        
        
    #_________________________________________________________________________
    def __initLibs(self):

        # Initialise libxml2 library
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)
        
        # Init xmlsec library
        if xmlsec.init() < 0:
            raise XMLSecDocError("xmlsec initialization failed.")

        
        # Check loaded library version
        if xmlsec.checkVersion() != 1:
            raise XMLSecDocError("xmlsec library version is not compatible.")


        # Init crypto library
        if xmlsec.cryptoAppInit(None) < 0:
            raise XMLSecDocError("Crypto initialization failed.")

        
        # Init xmlsec-crypto library
        if xmlsec.cryptoInit() < 0:
            raise XMLSecDocError("xmlsec-crypto initialization failed.")


    #_________________________________________________________________________       
    def __shutdownLibs(self):

        try:
            # Shutdown xmlsec-crypto library
            xmlsec.cryptoShutdown()
    
            # Shutdown crypto library
            xmlsec.cryptoAppShutdown()
    
            # Shutdown xmlsec library
            # Fudge - comment out to avoid error messages but may cause
            # mem leaks??
            #
            # P J Kershaw 24/03/06
            #xmlsec.shutdown()
    
            # Shutdown LibXML2
            libxml2.cleanupParser()
            
        except Exception, e:
            raise XMLSecDocError("Cleaning up xmlsec: %s" % e)


    def __str__(self):
        """String representation of doc - only applies if doc had been read
        or parsed"""
        if self.__libxml2Doc:
            return self.asString()
        else:
            return ""
    
    
    def __del__(self):
        """Ensure cleanup of libxml2 and xmlsec memory allocated"""
        self.__cleanup()
        self.__shutdownLibs()
        

    #_________________________________________________________________________
    def __libxml2ParseDoc(self, xmlTxt):
        """Wrapper for libxml2.parseDoc() - enables inclusion of flag to
        indicate to __cleanup method if libxml2.freeDoc() needs to be
        called."""
        
        if self.__libxml2Doc is not None and not self.__bLibxml2DocFreed:
            self.__libxml2Doc.freeDoc()

        # Create new doc and reset flag
        try:
            self.__libxml2Doc = libxml2.parseDoc(xmlTxt)

        except Exception, excep:
            raise XMLSecDocError("Error parsing document: %s" % str(excep))
        
        if self.__libxml2Doc is None or \
           self.__libxml2Doc.getRootElement() is None:
            raise XMLSecDocError("Error parsing Attribute Certificate")
            
        self.__bLibxml2DocFreed = False
         

    #_________________________________________________________________________
    def __libxml2ParseFile(self):

        """Wrapper for libxml2.parseFile() - enables inclusion of flag to
        indicate to __cleanup method if libxml2.freeDoc() needs to be
        called."""
        
        if self.__libxml2Doc is not None and not self.__bLibxml2DocFreed:
            self.__libxml2Doc.freeDoc()

        # Create new doc and reset flag
        try:
            self.__libxml2Doc = libxml2.parseFile(self.__filePath)

        except Exception, excep:
            raise XMLSecDocError("Error parsing file: %s" % str(excep))

        
        if self.__libxml2Doc is None or \
           self.__libxml2Doc.getRootElement() is None:
            raise XMLSecDocError(\
                "Error parsing Attribute Certificate \"%s\"" % self.__filePath)
            
        self.__bLibxml2DocFreed = False
    
       
    #_________________________________________________________________________
    def __libxml2XPathNewContext(self):

        """Wrapper for libxml2.parseDocxpathNewContext() - enables inclusion
        of flag to indicate to __cleanup method if libxml2.xpathFreeContext()
        needs to be called."""

        if self.__libxml2Doc is None:
            raise XMLSecDocError(\
                "self.__libxml2ParseDoc() must be called first")
        
        if self.__libxml2Ctxt is not None and not self.__bLibxml2CtxtFreed:
            self.__libxml2Ctxt.xpathFreeContext()

        # Create new context and reset flag
        self.__libxml2Ctxt = self.__libxml2Doc.xpathNewContext()
        if self.__libxml2Ctxt is None:
            raise XMLSecDocError("Error creating XPath context for \"%s\"" % \
                                  self.__filePath)

        self.__bLibxml2CtxtFreed = False


    #_________________________________________________________________________
    def __xmlsecDSigCtx(self, keysMngr=None):    
        """Wrapper for xmlsec.DSigCtx() - enables inclusion
        of flag to indicate to __cleanup method if xmlsec.DSigCtx.destroy()
        needs to be called."""

        # Check memory from any previous object has been released
        if self.__dSigCtxt is not None and not self.__bDSigCtxtFreed:
            self.__dSigCtxt.destroy()
       
        self.__dSigCtxt = xmlsec.DSigCtx(keysMngr)
        if self.__dSigCtxt is None:
            raise XMLSecDocError("Error creating signature context")

        self.__bDSigCtxtFreed = False


    #_________________________________________________________________________
    def __xmlsecEncCtx(self, keysMngr=None):    
        """Wrapper for xmlsec.EncCtx() - enables inclusion
        of flag to indicate to __cleanup method if xmlsec.EncCtx.destroy()
        needs to be called."""

        # Check memory from any previous object has been released
        if self.__encCtxt is not None and not self.__bEncCtxtFreed:
            self.__encCtxt.destroy()
       

        self.__encCtxt = xmlsec.EncCtx(keysMngr)
        if self.__encCtxt is None:
            raise XMLSecDocError("Error creating encryption context")

        self.__bEncCtxtFreed = False


    #_________________________________________________________________________
    def __xmlsecKeysMngr(self):
        """Wrapper for xmlsec.KeysMngr() - enables inclusion
        of flag to indicate to __cleanup method if xmlsec.KeysMngr.destroy()
        needs to be called."""

        # Check memory from any previous object has been released
        if self.__keysMngr is not None and not self.__bKeysMngrFreed:
            self.__keysMngr.destroy()
    
        self.__keysMngr = xmlsec.KeysMngr()
        if self.__keysMngr is None:
            raise XMLSecDocError("Failed to create keys manager.")

        self.__bKeysMngrFreed = False


    #_________________________________________________________________________     
    def __cleanup(self):
        """Private method for cleanup associated with libxml2/xmlsec"""

        # libxml2 doc created for parsing an existing Attribut Certificate/
        # signing a new certificate
        if self.__libxml2Doc is not None and not self.__bLibxml2DocFreed:
            self.__libxml2Doc.freeDoc()
            self.__bLibxml2DocFreed = True

        # libxml2 XPath Context associated with libxml2 doc object
        if self.__libxml2Ctxt is not None and not self.__bLibxml2CtxtFreed:
            self.__libxml2Ctxt.xpathFreeContext()
            self.__bLibxml2CtxtFreed = True

        # xmlsec Digital Signature object
        if self.__dSigCtxt is not None and not self.__bDSigCtxtFreed:
            self.__dSigCtxt.destroy()
            self.__bDSigCtxtFreed = True

        # xmlsec Encryption Context object
        if self.__encCtxt is not None and not self.__bEncCtxtFreed:
            self.__encCtxt.destroy()
            self.__bEncCtxtFreed = True
        
        # xmlsec Keys Manager
        if self.__keysMngr is not None and not self.__bKeysMngrFreed:
            self.__keysMngr.destroy()
            self.__bKeysMngrFreed = True
 



    def __getFilePath(self):
        """Get file path for file to be signed/encrypted."""
        return self.__filePath


    def __setFilePath(self, filePath):
        """Set file path for file to be signed/encrypted."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError("Document file path must be a valid string")
        
        self.__filePath = filePath


    def __delFilePath(self):
        """Prevent file path being deleted."""
        raise AttributeError("\"filePath\" cannot be deleted")
 
  
    # Publish attribute as read/write
    filePath = property(fget=__getFilePath,
                        fset=__setFilePath,
                        fdel=__delFilePath,
                        doc="File Path for XML document to apply security to")


    #_________________________________________________________________________
    def __setCertFilePathList(self, filePath):
        """File path for certificate used to sign document / 
        list of certificates used to check the signature of a document"""
        
        if isinstance(filePath, basestring):        
            self.__certFilePathList = [filePath]

        elif isinstance(filePath, list):
            self.__certFilePathList = filePath
                                            
        elif isinstance(filePath, tuple):
            self.__certFilePathList = list(filePath)

        else:
            raise XMLSecDocError(\
            "Signing Certificate file path must be a valid string or list")
 
  
    # Publish attribute as write only
    certFilePathList = property(fset=__setCertFilePathList,
        doc="File Path of certificate used to sign document / " + \
            "list of certificates used to check the signature of a doc")


    #_________________________________________________________________________
    def __setSigningKeyFilePath(self, filePath):
        """Set file path for certificate private key used to sign doc."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(\
                "Certificate key file path must be a valid string")
        
        self.__signingKeyFilePath = filePath

    # Publish attribute as write only
    signingKeyFilePath = property(fset=__setSigningKeyFilePath,
                doc="file path for certificate private key used to sign doc")



    #_________________________________________________________________________
    def __setEncrPubKeyFilePath(self, filePath):
        """Set file path for certificate publiv key used to decrypt doc."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(\
                "Certificate key file path must be a valid string")

        self.__encrPubKeyFilePath = filePath

    # Publish attribute as write only
    encrPubKeyFilePath = property(fset=__setEncrPubKeyFilePath,
        doc="file path for certificate publiv key used to decrypt doc")


    #_________________________________________________________________________
    def __setEncrPriKeyFilePath(self, filePath):
        """Set file path for certificate private key used to decrypt doc."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(\
                "Certificate key file path must be a valid string")
        
        self.__encrPriKeyFilePath = filePath

    # Publish attribute as write only
    encrPriKeyFilePath = property(fset=__setEncrPriKeyFilePath,
        doc="file path for certificate private key used to decrypt doc")


    #_________________________________________________________________________
    def asString(self, filePath=None, stripXMLhdr=False):
        """Return certificate file content as a string"""
        
        # Check libxml2.xmlDoc object has been instantiated - if not call
        # read method
        if self.__libxml2Doc is None:
            if filePath is None:
                raise XMLSecDocError(\
                    "A file must be parsed first for asString()")
                    
            self.read(filePath)

        try:
            # Make a buffer
            f = StringIO()
            buf = libxml2.createOutputBuffer(f, 'UTF-8')

            # Write to buffer
            self.__libxml2Doc.saveFormatFileTo(buf, 'UTF-8', 0)


            # Return string content
            if stripXMLhdr:
                return re.sub("<\?xml.*>\s", "", f.getvalue())
            else:
                return f.getvalue()

        except Exception, e:
            raise XMLSecDocError("Error outputting document as a string:" % \
                                 e)


    #_________________________________________________________________________
    def parse(self, xmlTxt):

        """Parse string containing XML into a libxml2 document to allow
        signature validation"""

        self.__libxml2ParseDoc(xmlTxt)


    #_________________________________________________________________________
    def read(self, filePath=None):

        """Read XML into a libxml2 document to allow signature validation"""

        # Check for file path passed as input argument otherwise use member
        # variable
        if filePath is not None:
            self.__filePath = filePath

        self.__libxml2ParseFile()


    #_________________________________________________________________________
    def write(self, filePath=None, bSign=False, xmlTxt=None, **signKeys):

        """Write XML document applying digital signature

        filePath:               file path for XML output
                            
        bSign:                  flag defaults to False to NOT sign the
                                document.  Explicitly set to True to sign
                                the new certificate using the private key
                                and certificate.

        xmlTxt:                 string containing formatted xml text for
                                signing.  If no text is provided, the method
                                createXML() is called to return the text.
                                Derived classes should implement this method.

        Keyword arguments required by XMLSecDoc.sign():
        
        signingKeyFilePath:     file path to private key file of Attribute
                                Authority - may also be set in  __init__

        signingKeyPwd:          password for signing key file.

        certFilePathList:       file paths to certificate files
                                """

        
        if filePath is not None:
            self.setFilePath(filePath)

        
        # Set up libxml2 object from string containing XML for writing
        if xmlTxt is None: xmlTxt = self.createXML()

        
        # Apply digital signature of Attribute Authority
        if bSign: self.sign(xmlTxt=xmlTxt, **signKeys)


        # Ensure libxml2 doc has been created for document to be written
        #  A valid one should be present if sign() was called above
        if self.__libxml2Doc is None: self.__libxml2ParseDoc(xmlTxt)

            
        # Updated content is held in libxml2 doc instance.  Use this to
        # write new certificate to file
        self.__libxml2Doc.saveFormatFile(self.__filePath, True)


    #_________________________________________________________________________
    def createXML(self):

        """VIRTUAL method - derived class should implement -
        Create text for output and return as a string"""
        
        raise XMLSecDocError(\
                    "Virtual function: Derived class should implement.")

        return None


    #_________________________________________________________________________
    def sign(self,
             xmlTxt=None,
             signingKeyFilePath=None,
             signingKeyPwd=None,
             certFilePathList=None,
	         inclX509Cert=True,
             inclX509SubjName=True,
	         inclX509IssSerial=True,
             rtnAsString=False):
        """Sign XML document using an X.509 certificate private key

        xmlTxt:                 string buffer containing xml to be signed. If
                                not provided, calls XMLSecDoc.createXML().
                                This is a virtual method so must be defined
                                in a derived class.
                            
        signingKeyFilePath:     file path to private key file used to sign
                                the document

        signingKeyPwd:          password for signing key file.
        
        certFilePathList:    	include certificate of signer 
	    inclX509Cert:		    include MIME encoded content of X.509 
				                certificate that will sign the document
        inclX509SubjName:	    include subject name of signing X.509 
				                certificate.
	    inclX509IssSerial:	    include issuer name and serial inumber in
				                signature
                                	
        rtnAsString:            This method returns None by default.  Set to 
                                True to override and return the signed
                                result instead as a string."""

        # Create string buffer from virtual function if not passed
        # as input argument - derived class must implement 
        if xmlTxt is None:
            xmlTxt = self.createXML()

            
        # Set private key file
        if signingKeyFilePath is not None:
            self.__setSigningKeyFilePath(signingKeyFilePath)            


        # Public certificate file 
        if certFilePathList is not None:
            self.__setCertFilePathList(certFilePathList)


        # Check files for read access
        try:
            if not os.access(self.__signingKeyFilePath, os.R_OK):
                raise XMLSecDocError("not found or no read access")
                                     
        except Exception, e:
            raise XMLSecDocError(\
                "Private key file path is not valid: \"%s\": %s" % \
                (self.__signingKeyFilePath, str(e)))

        
        try:
            if not os.access(self.__certFilePathList[0], os.R_OK):
                raise XMLSecDocError("not found or no read access")
            
        except Exception, e:
            raise XMLSecDocError(\
                "Signing certificate file path is not valid: \"%s\": %s" % \
                (self.__certFilePathList[0], str(e)))


        # Create libxml2 doc instance
        self.__libxml2ParseDoc(xmlTxt)            


        # Create signature template for RSA-SHA1 enveloped signature
        sigNode = xmlsec.TmplSignature(self.__libxml2Doc,
                                       xmlsec.transformExclC14NId(),
                                       xmlsec.transformRsaSha1Id(),
                                       None)
        if sigNode is None:
            raise XMLSecDocError("Error creating signature template")

        
        # Add <dsig:Signature/> node to the doc
        self.__libxml2Doc.getRootElement().addChild(sigNode)


        # Add reference
        refNode = sigNode.addReference(xmlsec.transformSha1Id(),
                                       None, None, None)
        if refNode is None:
            raise XMLSecDocError(
                "Error adding reference to signature template")


        # Add enveloped transform
        if refNode.addTransform(xmlsec.transformEnvelopedId()) is None:
            raise XMLSecDocError(\
                "Error adding enveloped transform to reference")

 
        # Add <dsig:KeyInfo/> and <dsig:X509Data/>
        keyInfoNode = sigNode.ensureKeyInfo(None)
        if keyInfoNode is None:
            raise XMLSecDocError("Error adding key info")


        x509DataNode = keyInfoNode.addX509Data()
        if x509DataNode is None:
            raise XMLSecDocError("Error adding X509Data node")


        # Add extra X509Data info
        if inclX509Cert:
            if xmlsec.addChild(x509DataNode,
			                   xmlsec.NodeX509Certificate) is None:
                raise XMLSecDocError("Error adding %s node" % \
                                     xmlsec.NodeX509Certificate)

        if inclX509SubjName:
            if xmlsec.addChild(x509DataNode,
			                   xmlsec.NodeX509SubjectName) is None:
                raise XMLSecDocError("Error adding %s node" % \
                                     xmlsec.NodeX509SubjectName)

        if inclX509IssSerial:
            if xmlsec.addChild(x509DataNode,
			                   xmlsec.NodeX509IssuerSerial) is None:
                raise XMLSecDocError("Error adding %s node" % \
                                     xmlsec.NodeX509IssuerSerial)


        # Create signature context
        self.__xmlsecDSigCtx()

        
        # Load private key
        self.__dSigCtxt.signKey = xmlsec.cryptoAppKeyLoad(
                                                    self.__signingKeyFilePath,
                                                    xmlsec.KeyDataFormatPem,
                                                    signingKeyPwd,
                                                    None, 
                                                    None)
        if self.__dSigCtxt.signKey is None:
            raise XMLSecDocError(\
                "Error loading private pem key from \"%s\"" % \
                self.__signingKeyFilePath)


        # Load certificate and add to the key
        if xmlsec.cryptoAppKeyCertLoad(self.__dSigCtxt.signKey,
                                       self.__certFilePathList[0],
                                       xmlsec.KeyDataFormatPem) < 0:
            raise XMLSecDocError("Error loading pem certificate \"%s\"" % \
                                  self.__certFilePathList[0])


        # Set key name to the file name
        if self.__dSigCtxt.signKey.setName(self.__signingKeyFilePath) < 0:
            raise XMLSecDocError(\
                "Error setting key name for key from \"%s\"" % \
                  self.__signingKeyFilePath)


        # Sign the template
        if self.__dSigCtxt.sign(sigNode) < 0:
            raise XMLSecDocError("Signature failed")

            
        # Return as required
        if rtnAsString:
            return self.asString()
        

    #_________________________________________________________________________
    def isValidSig(self,
                   xmlTxt=None,
                   filePath=None,
                   certFilePathList=None):

        """
        Verify XML signature in file.  Returns True if valid otherwise
        False.

        xmlTxt:                 string buffer containing the text from the XML
                                file to be checked.  If omitted, the
                                filePath argument is used instead.

        filePath:               file path to XML file to be checked.  This
                                argument is used if no xmlTxt was provided.
                                If filePath itself is omitted the file set
                                by self.__filePath is read instead.

        certFilePathList:       Certificate used to sign the document.
                                """

        if certFilePathList is not None:
            self.__setCertFilePathList(certFilePathList)

        
        # Check Certificate files for read access
        if not self.__certFilePathList:                
            raise XMLSecDocError("No certificate files set for check")
            

        # Create and initialize keys manager
        self.__xmlsecKeysMngr()

        if xmlsec.cryptoAppDefaultKeysMngrInit(self.__keysMngr) < 0:
            raise XMLSecDocError("Failed to initialize keys manager.")

        
        # Load certificate(s) list should contain certificate used to sign the
        # document
        for certFilePath in self.__certFilePathList:
            if self.__keysMngr.certLoad(certFilePath,
                                        xmlsec.KeyDataFormatPem,
                                        xmlsec.KeyDataTypeTrusted) < 0:
                raise XMLSecDocError(\
                    "Error loading signing certificate \"%s\"" % certFilePath)


        # If 'xmlTxt' was input, update libxml2 doc instance with it's content
        if xmlTxt is not None: 
            self.__libxml2ParseDoc(xmlTxt)
            
        elif filePath:
            # Likewise, if a new file was set
            self.__setFilePath(filePath)                
            self.__libxml2ParseFile()
        
        # libxml2Doc should now be instantiated - from xmlTxt, an input file
        # or previous call to parse or read document
        if not self.__libxml2Doc:
            raise XMLSecDocError("document is invalid")

       
        # Find start node
        dSigNode = xmlsec.findNode(self.__libxml2Doc.getRootElement(),
                                   xmlsec.NodeSignature, xmlsec.DSigNs)
        if dSigNode is None:
            raise XMLSecDocError(\
                "Start node not found in \"%s\"" % self.__filePath)

 
        # Create signature context
        self.__xmlsecDSigCtx(self.__keysMngr)


        # Verify signature
        if self.__dSigCtxt.verify(dSigNode) < 0:
            raise XMLSecDocError("Error verifying signature.")


        # Return True if signature is OK, False otherwise
        return self.__dSigCtxt.status == xmlsec.DSigStatusSucceeded


    #_________________________________________________________________________
    def getKeyInfoData(self):
        """Return tags associated with KeyInfo tag of digital signature as a
        dictionary

        Call after isValidSig() or read()"""

        keyInfo = {}

        
        # Find start node
        dSigNode = xmlsec.findNode(self.__libxml2Doc.getRootElement(),
                                   xmlsec.NodeSignature, 
                                   xmlsec.DSigNs)
        if dSigNode is None:
            raise XMLSecDocError(\
                "Start node not found in \"%s\"" % self.__filePath)
        
            
        keyInfoNode = xmlsec.findNode(dSigNode,
                                      xmlsec.NodeKeyInfo,
                                      xmlsec.DSigNs)
        if keyInfoNode is None:
            raise XMLSecDocError("KeyInfo node not found in \"%s\"" % \
                                 self.__filePath)

            
        keyNameNode = xmlsec.findNode(keyInfoNode,
                                      xmlsec.NodeKeyName,
                                      xmlsec.DSigNs)
        if keyNameNode is not None:
            keyInfo[keyNameNode.name] = keyNameNode.content

            
        x509DataNode = xmlsec.findNode(keyInfoNode,
                                       xmlsec.NodeX509Data,
                                       xmlsec.DSigNs)
        if x509DataNode is None:
            # Return the keyInfo found up to this point
            return keyInfo

        keyInfo[x509DataNode.name] = {}

        
        x509CertificateNode = xmlsec.findNode(x509DataNode,
                                              xmlsec.NodeX509Certificate,
                                              xmlsec.DSigNs)
        if x509CertificateNode is not None:
            keyInfo[x509DataNode.name][x509CertificateNode.name] = \
                                                x509CertificateNode.content


        x509SubjectNameNode = xmlsec.findNode(x509DataNode,
                                              xmlsec.NodeX509SubjectName,
                                              xmlsec.DSigNs)
        if x509SubjectNameNode is not None:
            keyInfo[x509DataNode.name][x509SubjectNameNode.name] = \
                                                x509SubjectNameNode.content


        x509IssuerSerialNode = xmlsec.findNode(x509DataNode,
                                               xmlsec.NodeX509IssuerSerial,
                                               xmlsec.DSigNs)
        if x509IssuerSerialNode is None:
            # Return the keyInfo found up to this point
            return keyInfo


        keyInfo[x509DataNode.name][x509IssuerSerialNode.name] = {}
        
        x509IssuerNameNode = xmlsec.findNode(x509IssuerSerialNode,
                                             xmlsec.NodeX509IssuerName,
                                             xmlsec.DSigNs)
        if x509IssuerNameNode is not None:            
            keyInfo[x509DataNode.name][x509IssuerSerialNode.name]\
                    [x509IssuerNameNode.name] = x509IssuerNameNode.content


        x509SerialNumberNode = xmlsec.findNode(x509IssuerSerialNode,
                                               xmlsec.NodeX509SerialNumber,
                                               xmlsec.DSigNs)
        if x509SerialNumberNode is not None:            
            keyInfo[x509DataNode.name][x509IssuerSerialNode.name]\
                    [x509SerialNumberNode.name] = x509SerialNumberNode.content


        return keyInfo
    

    #_________________________________________________________________________
    def encrypt(self,
                xmlTxt=None, 
                filePath=None, 
                encrPubKeyFilePath=None,
                inclX509SubjName=True,
                inclX509IssSerial=True,
                rtnAsString=False):
        """Encrypt a document using recipient's public key

        Encrypts xml file using a dynamically created template, a session 
        triple DES key and an RSA key from keys manager.
        
        xmlTxt:                 string buffer containing the text from the XML
                                file to be encrypted.  If omitted, the
                                filePath argument is used instead.

        filePath:               file path to XML file to be encrypted.  This
                                argument is used if no xmlTxt was provided.
                                If filePath itself is omitted the file set
                                by self.__filePath is read instead.
                                
        encrPubKeyFilePath:     file path to RSA public key file used to
                                encrypt the document.
                                
        inclX509SubjName:       include subject name of signing X.509 
                                certificate.
        inclX509IssSerial:      include issuer name and serial number in
                                signature    
        
        rtnAsString:            This method returns None by default.  Set to 
                                True to override and return the encrypted
                                result instead as a string."""
        
        if encrPubKeyFilePath:
            self.__setEncrPubKeyFilePath(encrPubKeyFilePath)
            
            
        # Create file based Keys manager to load the public key used to 
        self.__xmlsecKeysMngr()


        if xmlsec.cryptoAppDefaultKeysMngrInit(self.__keysMngr) < 0:
            raise XMLSecDocError("Error initializing keys manager.")


        # Load public RSA key
        #
        # Nb. 7 value corresponds to XMLSec "xmlSecKeyDataFormatCertPem" - 
        # there isn't a variable set up for it in pyXMLSec
        encrKey = xmlsec.cryptoAppKeyLoad(self.__encrPubKeyFilePath, 
                                          7,
                                          None, 
                                          None, 
                                          None);
        if encrKey is None:
            raise XMLSecDocError(\
                "Error loading RSA public key from file \"%s\"" % \
                self.__encrPubKeyFilePath)


        # Set key name to the file name, this is just an example!
        if encrKey.setName(self.__encrPubKeyFilePath) < 0:
            raise XMLSecDocError(\
                "Error setting key name for RSA public key from \"%s\"" % \
                self.__encrPubKeyFilePath)


        # Add key to keys manager, from now on keys manager is responsible
        # for destroying key
        if xmlsec.cryptoAppDefaultKeysMngrAdoptKey(self.__keysMngr, 
                                                   encrKey) < 0:
            raise XMLSecDocError(\
                "Error adding RSA public key from \"%s\" to keys manager" % \
                self.__encrPubKeyFilePath)

   
        # If 'xmlTxt' was input update libxml2 doc instance with it's content
        if xmlTxt: 
            self.__libxml2ParseDoc(xmlTxt)
        else:
            # Update file path if set - otherwise, existing setting  
            # self.__filePath will be used.
            if filePath:
                self.__setFilePath(filePath)
                
                # Read XML document from file
                self.__libxml2ParseFile()

    
        # Create encryption template to encrypt XML file and replace 
        # its content with encryption result
        encrNode = xmlsec.TmplEncData(self.__libxml2Doc, 
                                      xmlsec.transformDes3CbcId(),
                                      None, 
                                      xmlsec.TypeEncElement, 
                                      None, 
                                      None)
        if encrNode is None:
            raise XMLSecDocError("Error creating encryption template")

    
        # Put encrypted data in the <enc:CipherValue/> node
        if encrNode.ensureCipherValue() is None:
            raise XMLSecDocError("Error adding CipherValue node")
 
    
        # add <dsig:KeyInfo/>
        keyInfoNode = encrNode.ensureKeyInfo(None)
        if keyInfoNode is None:
            XMLSecDocError("Error adding key info node")

    
        # Add <enc:EncryptedKey/> to store the encrypted session key
        encrKeyNode = keyInfoNode.addEncryptedKey(xmlsec.transformRsaOaepId(), 
                                                  None, 
                                                  None, 
                                                  None)
        if encrKeyNode is None:
            XMLSecDocError("Error adding encryption key info node")

    
        # Put encrypted key in the <enc:CipherValue/> node
        if encrKeyNode.ensureCipherValue() is None:
            XMLSecDocError("Error adding CipherValue node")

    
        keyInfoNode2 = encrKeyNode.ensureKeyInfo(None)
        if keyInfoNode2 is None:
            XMLSecDocError("Error adding public key <KeyInfo>")
           
        
        # Add info about public key in <KeyInfo> <X509Data> if any of X.509
        # flags are set
        if inclX509SubjName or inclX509IssSerial:
            
            keyInfoNode2 = encrKeyNode.ensureKeyInfo(None)
            if keyInfoNode2 is None:
                XMLSecDocError("Error adding public key <KeyInfo>")
                cleanup(self.__libxml2Doc, encrNode)
        
        
            x509DataNode = keyInfoNode2.addX509Data()
            if x509DataNode is None:
                raise XMLSecDocError("Error adding <X509Data> node")
    
    
            # Individual X509Data components
            if inclX509SubjName:
                if xmlsec.addChild(x509DataNode,
                                   xmlsec.NodeX509SubjectName) is None:
                    raise XMLSecDocError("Error adding <%s> node" % \
                                         xmlsec.NodeX509SubjectName)
        
            if inclX509IssSerial:
                if xmlsec.addChild(x509DataNode,
                                   xmlsec.NodeX509IssuerSerial) is None:
                    raise XMLSecDocError("Error adding <%s> node" % \
                                         xmlsec.NodeX509IssuerSerial)
    
            
        # Create encryption context
        self.__xmlsecEncCtx(self.__keysMngr)

    
        # Generate a Triple DES key
        self.__encCtxt.encKey = xmlsec.keyGenerate(xmlsec.keyDataDesId(), 
                                                   192,
                                                   xmlsec.KeyDataTypeSession)
        if self.__encCtxt.encKey is None:
            raise XMLSecDocError("Error generating session DES key")
    
    
        # Encrypt the data
        if self.__encCtxt.xmlEncrypt(encrNode, 
                                     self.__libxml2Doc.getRootElement()) < 0:
            raise XMLSecDocError("Encryption failed")
    

        # Success
        if rtnAsString:
            return self.asString()
 
 
    #_________________________________________________________________________
    def decrypt(self, 
                xmlTxt=None, 
                filePath=None, 
                encrPriKeyFilePath=None,
                encrPriKeyPwd=None,
                rtnAsString=False):
        """Decrypt a document using a private key of public/private key pair
        
        xmlTxt:                 string buffer containing the text from the XML
                                file to be decrypted.  If omitted, the
                                filePath argument is used instead.

        filePath:               file path to XML file to be decrypted.  This
                                argument is used if no xmlTxt was provided.
                                If filePath itself is omitted the file set
                                by self.__filePath is read instead.
                                
        encrPriKeyFilePath:     file path to private key file used to decrypt

        encrPriKeyPwd:          password for private key file.
        
        rtnAsString:            This method returns None by default.  Set to 
                                True to override and return the decrypted
                                result instead as a string."""
        
        if encrPriKeyFilePath:
            self.__setEncrPriKeyFilePath(encrPriKeyFilePath)
            
            
        # Create Keys manager to hold the private key used to decrypt
        self.__xmlsecKeysMngr()

        if xmlsec.cryptoAppDefaultKeysMngrInit(self.__keysMngr) < 0:
            raise XMLSecDocError("Error initializing keys manager.")

        
        encrKey = xmlsec.cryptoAppKeyLoad(self.__encrPriKeyFilePath, 
                                          xmlsec.KeyDataFormatPem, 
                                          encrPriKeyPwd, 
                                          None, 
                                          None)
        if encrKey is None:
            raise XMLSecDocError(\
                "Error loading private key from file \"%s\"" % \
                self.__encrPriKeyFilePath)
 
        
        # Add key to keys manager, from now on keys manager is responsible
        # for destroying key
        if xmlsec.cryptoAppDefaultKeysMngrAdoptKey(self.__keysMngr, 
                                                   encrKey) < 0:
            raise XMLSecDocError(\
                "Error adding private key from \"%s\" to keys manager" % \
                self.__encrPriKeyFilePath)
 
   
        # If 'xmlTxt' was input update libxml2 doc instance with it's content
        if xmlTxt: 
            self.__libxml2ParseDoc(xmlTxt)
        else:
            # Update file path if set - otherwise, existing setting  
            # self.__filePath will be used.
            if filePath:
                self.__setFilePath(filePath)
            
            # Read XML document from file
            self.__libxml2ParseFile()
              
               
        # Find start node
        encrNode = xmlsec.findNode(self.__libxml2Doc.getRootElement(), 
                                   xmlsec.NodeEncryptedData,
                                   xmlsec.EncNs)
        if encrNode is None:
            raise XMLSecDocError("Start node not found")
        
        
        # Create encryption context
        self.__xmlsecEncCtx(self.__keysMngr)

    
        # Decrypt the data
        if self.__encCtxt.decrypt(encrNode) < 0 or \
           self.__encCtxt.result is None:
            raise XMLSecDocError("Decryption failed")
    
        # Check
        if not self.__encCtxt.resultReplaced:
            raise XMLSecDocError("Expecting XML data result")
    
        # Success
        if rtnAsString:
            return self.asString()


    #_________________________________________________________________________
    def symEncrypt(self, 
                   xmlTxt=None, 
                   filePath=None,
                   keyBinFilePath=None, 
                   rtnAsString=False):
        """Encrypt document using symmetric key

        xmlTxt:                 string buffer containing the text from the XML
                                file to be encrypted.  If omitted, the
                                filePath argument is used instead.

        filePath:               file path to XML file to be encrypted.  This
                                argument is used if no xmlTxt was provided.
                                If filePath itself is omitted the file set
                                by self.__filePath is read instead.
                                
        keyBinFilePath:         file path to binary file containing DES key
                                used to encrypt.  If none provided, 
                                dynamically generate one.

        rtnAsString:            This method returns None by default.  Set to 
                                True to override and return the encrypted
                                result instead as a string."""

   
        # If 'xmlTxt' was input update libxml2 doc instance with it's content
        if xmlTxt: 
            self.__libxml2ParseDoc(xmlTxt)
        elif filePath:
            # Update file path if set - otherwise, existing setting  
            # self.__filePath will be used.            
            self.__setFilePath(filePath)
            
            # Read XML document from file
            self.__libxml2ParseFile()

        
        # Create encryption template to encrypt XML file and replace 
        # its content with encryption result
        encrNode = xmlsec.TmplEncData(self.__libxml2Doc, 
                                      xmlsec.transformDes3CbcId(),
                                      None, 
                                      xmlsec.TypeEncElement, 
                                      None, 
                                      None)
        if encrNode is None:
            raise XMLSecDocError("Error creating encryption template")
    
        # Put encrypted data in the <enc:CipherValue/> node
        if encrNode.ensureCipherValue() is None:
            raise XMLSecDocError("Error adding CipherValue node")
    
        # add <dsig:KeyInfo/>
        keyInfoNode = encrNode.ensureKeyInfo(None)
        if keyInfoNode is None:
            XMLSecDocError("Error adding key info node")
      
      
        if keyInfoNode.addKeyName() is None:
            XMLSecDocError("Error adding key name")
            
            
        # Create encryption context, no keys manager is needed
        self.__xmlsecEncCtx()
    
        if keyBinFilePath:
            # Load DES key from file, assume that there is no password
            self.__encCtxt.encKey = xmlsec.keyReadBinaryFile(\
                                                   xmlsec.keyDataDesId(), 
                                                   keyBinFilePath)                
        else:
            # Generate a Triple DES key dynamically
            self.__encCtxt.encKey = xmlsec.keyGenerate(xmlsec.keyDataDesId(), 
                                                   192,
                                                   xmlsec.KeyDataTypeSession)

        if self.__encCtxt.encKey is None:
            raise XMLSecDocError("Error setting DES key")
    
     
        # Set key name
        if self.__encCtxt.encKey.setName(os.path.basename(keyBinFilePath))<0:
            raise XMLSecDocError("Error setting key name")

    
        # Encrypt the data
        if self.__encCtxt.xmlEncrypt(encrNode, 
                                     self.__libxml2Doc.getRootElement()) < 0:
            raise XMLSecDocError("Encryption failed")
    
        # Success
        if rtnAsString:
            return self.asString()
        
        
    #_________________________________________________________________________
    def symDecrypt(self,
                   xmlTxt=None, 
                   filePath=None,
                   keyBinFilePath=None,
                   rtnAsString=False):                       
        """Decrypt XML encrypted with a symmetric key
        
        xmlTxt:                 string buffer containing the text from the XML
                                file to be checked.  If omitted, the
                                filePath argument is used instead.

        filePath:               file path to XML file to be checked.  This
                                argument is used if no xmlTxt was provided.
                                If filePath itself is omitted the file set
                                by self.__filePath is read instead.
                                
        keyBinFilePath:         file path to binary file containing DES key
                                used to decrypt

        rtnAsString:            This method returns None by default.  Set to 
                                True to override and return the decrypted
                                result instead as a string."""
                                
        # Load key into keys manager
        self.__xmlsecKeysMngr()

        if xmlsec.cryptoAppDefaultKeysMngrInit(self.__keysMngr) < 0:
            raise XMLSecDocError("Error initializing keys manager.")
        
        # Load DES key
        encrKey = xmlsec.keyReadBinaryFile(xmlsec.keyDataDesId(), 
                                           keyBinFilePath)
        if encrKey is None:
            raise XMLSecDocError(\
                "Error loading DES key from binary file \"%s\"" % \
                keyBinFilePath)

        # Add key to keys manager, from now on keys manager is responsible
        # for destroying key
        if xmlsec.cryptoAppDefaultKeysMngrAdoptKey(self.__keysMngr, 
                                                   encrKey) < 0:
            raise XMLSecDocError(\
                "Error adding DES key from \"%s\" to keys manager" % \
                keyBinFilePath)

    
        # If 'xmlTxt' was input update libxml2 doc instance with it's content
        if xmlTxt: 
            self.__libxml2ParseDoc(xmlTxt)
        else:
            # Update file path if set - otherwise, existing setting  
            # self.__filePath will be used.
            if filePath:
                self.__setFilePath(filePath)
            
            # Read XML document from file
            self.__libxml2ParseFile()
              
               
        # Find start node
        encrNode = xmlsec.findNode(self.__libxml2Doc.getRootElement(), 
                                   xmlsec.NodeEncryptedData,
                                   xmlsec.EncNs)
        if encrNode is None:
            raise XMLSecDocError("Start node not found in \"%s\"" % \
                                                            self.__filePath)
               
        # Create encryption context
        self.__xmlsecEncCtx(self.__keysMngr)

    
        # Decrypt the data
        if self.__encCtxt.decrypt(encrNode) < 0 or \
           self.__encCtxt.result is None:
            raise XMLSecDocError("Decryption failed")
    
        # Check
        if not self.__encCtxt.resultReplaced:
            raise XMLSecDocError("Expecting XML data result")
    
        # Success
        if rtnAsString:
            return self.asString()


    def generateSymKey(self, keyLength=192, outFilePath=None):
        """Generate a symmetric key for encrypting a document
        
        keyLength:    length of key in characters - must 192 or greater
        outFilePath:  if a file path is provided, write the key to this file
        """
        
        if keyLength < 192:
            keyLength = 192
            
        try:
            key = base64.b64encode(os.urandom(keyLength))[0:192]
        except Exception, e:
            raise XMLSecDocError("Error creating symmetric key")
        
        if outFilePath:
            try:
                open(outFilePath, "w").write(key)
                
            except IOError, e:
                raise XMLSecDocError(\
                    "Error writing key to file \"%s\": %s" % \
                                     (e.filename, e.strerror))
            except Exception, e:
                raise XMLSecDocError("Error writing key to file \"%s\"" %\
                                     outFilePath)
                                 
        return key

