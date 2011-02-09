"""NDG Attribute Certificate (Authentication -or Access- Token)

Nerc Data Grid Project

P J Kershaw 05/04/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later."""

cvsID = '$Id$'


from UserDict import UserDict
import types
import os

# Use to create buffer for string output for asString()
from cStringIO import StringIO

# xmlsec requires libxml2
import libxml2

# XML security module
import xmlsec




class xmlSigDocError(Exception):

    """Exception handling for NDG XML Signature class."""
    
    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg




class xmlSigDoc:

    """Implements Digital Signature for XML Document."""

    def __init__(self,
                 filePath=None,
                 signingKeyFilePath=None,
                 certFilePathList=None):

        """Initialisation - Attribute Certificate file path may be specified.
        Also, holder and issuer details and signing authority key and
        certificate."""

        
        self.__filePath = None
        self.__signingKeyFilePath = None
        self.__certFilePathList = None


        if filePath is not None:

            if not isinstance(filePath, basestring):
                raise xmlSigDocError("Input key file path is %s" % \
                                     type(filePath) + \
                                     ": string type expected")

            self.__filePath = filePath


        # Private key file to be used to sign the document
        if signingKeyFilePath is not None:
            self.setSigningKeyFilePath(signingKeyFilePath)


        # This may be either of:
        # 1) Certificate file to be used for signing document
        # 2) list of files one of which is the certificate used to sign the
        # document being checked
        if certFilePathList is not None:
            self.setCertFilePathList(certFilePathList)


        # Keep track of libxml2/libxmlsec variables which need explicit
        # freeing
        self.__libxml2Doc = None
        self.__bLibxml2DocFreed = False
            
        self.__libxml2Ctxt = None
        self.__bLibxml2CtxtFreed = False

        self.__dSigCtxt = None
        self.__bDSigCtxtFreed = False

        self.__keysMngr = None
        self.__bkeysMngrFreed = False


        # Initialise libxml2 library
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)


        # Init xmlsec library
        if xmlsec.init() < 0:
            raise xmlSigDocError("xmlsec initialization failed.")

        
        # Check loaded library version
        if xmlsec.checkVersion() != 1:
            raise xmlSigDocError("xmlsec library version is not compatible.")


        # Init crypto library
        if xmlsec.cryptoAppInit(None) < 0:
            raise xmlSigDocError("Crypto initialization failed.")

        
        # Init xmlsec-crypto library
        if xmlsec.cryptoInit() < 0:
            raise xmlSigDocError("xmlsec-crypto initialization failed.")



        
    def __del__(self):

        """Ensure cleanup of libxml2 and xmlsec memory allocated"""
        
        self.__cleanup()
      
        # Shutdown xmlsec-crypto library
        xmlsec.cryptoShutdown()

        # Shutdown crypto library
        xmlsec.cryptoAppShutdown()

        # Shutdown xmlsec library
        xmlsec.shutdown()

        # Shutdown LibXML2
        libxml2.cleanupParser()
        



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
            raise xmlSigDocError("Error parsing dccument: %s" % str(excep))
        
        if self.__libxml2Doc is None or \
           self.__libxml2Doc.getRootElement() is None:
            raise xmlSigDocError("Error parsing Attribute Certificate")
            
        self.__bLibxml2DocFreed = False
         



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
            raise xmlSigDocError("Error parsing file: %s" % str(excep))

        
        if self.__libxml2Doc is None or \
           self.__libxml2Doc.getRootElement() is None:
            raise xmlSigDocError(\
                "Error parsing Attribute Certificate \"%s\"" % self.__filePath)
            
        self.__bLibxml2DocFreed = False
       



    def __libxml2XPathNewContext(self):

        """Wrapper for libxml2.parseDocxpathNewContext() - enables inclusion
        of flag to indicate to __cleanup method if libxml2.xpathFreeContext()
        needs to be called."""

        if self.__libxml2Doc is None:
            raise xmlSigDocError(\
                "self.__libxml2ParseDoc() must be called first")
        
        if self.__libxml2Ctxt is not None and not self.__bLibxml2CtxtFreed:
            self.__libxml2Ctxt.xpathFreeContext()

        # Create new context and reset flag
        self.__libxml2Ctxt = self.__libxml2Doc.xpathNewContext()
        if self.__libxml2Ctxt is None:
            raise xmlSigDocError("Error creating XPath context for \"%s\"" % \
                                  self.__filePath)

        self.__bLibxml2CtxtFreed = False




    def __xmlsecDSigCtx(self, keysMngr=None):
    
        """Wrapper for xmlsec.DSigCtx() - enables inclusion
        of flag to indicate to __cleanup method if xmlsec.DSigCtx.destroy()
        needs to be called."""

        # Check memory from any previous object has been released
        if self.__dSigCtxt is not None and not self.__bDSigCtxtFreed:
            self.__dSigCtxt.destroy()
       
        self.__dSigCtxt = xmlsec.DSigCtx(keysMngr)
        if self.__dSigCtxt is None:
            raise xmlSigDocError("Error creating signature context")

        self.__bDSigCtxtFreed = False




    def __xmlsecKeysMngr(self):

        """Wrapper for xmlsec.KeysMngr() - enables inclusion
        of flag to indicate to __cleanup method if xmlsec.KeysMngr.destroy()
        needs to be called."""

        # Check memory from any previous object has been released
        if self.__keysMngr is not None and not self.__bkeysMngrFreed:
            self.__keysMngr.destroy()
    
        self.__keysMngr = xmlsec.KeysMngr()
        if self.__keysMngr is None:
            raise xmlSigDocError("Failed to create keys manager.")

        self.__bkeysMngrFreed = False



         
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
        
        # xmlsec Keys Manager
        if self.__keysMngr is not None and not self.__bkeysMngrFreed:
            self.__keysMngr.destroy()
            self.__bkeysMngrFreed = True




    def getFilePath(self):
        """Get file path for file to be signed."""
        return self.__filePath




    def setFilePath(self, filePath):
        """Set file path for file to be signed."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise xmlSigDocError("Document file path must be a valid string")
        
        self.__filePath = filePath




    def setCertFilePathList(self, filePath):
        """Set file path for certificate used to sign document/as list
        of certificates to check the signature of a document"""
        
        if isinstance(filePath, basestring):        
            self.__certFilePathList = [filePath]

        elif isinstance(filePath, list):
            self.__certFilePathList = filePath

        else:
            raise xmlSigDocError(\
            "Signing Certificate file path must be a valid string or list")




    def setSigningKeyFilePath(self, filePath):
        """Set file path for certificate private key used to sign doc."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise xmlSigDocError(\
                "Certificate key file path must be a valid string")
        
        self.__signingKeyFilePath = filePath



    def asString(self, filePath=None):
        """Return certificate file content as a string"""
        
        # Check libxml2.xmlDoc object has been instantiated - if not call
        # read method
        if self.__libxml2Doc is None:
            self.read(filePath)

        try:
            # Make a buffer
            f = StringIO()
            buf = libxml2.createOutputBuffer(f, 'UTF-8')

            # Write to buffer
            self._xmlSigDoc__libxml2Doc.saveFormatFileTo(buf, 'UTF-8', 0)

            # Return string content
            return f.getvalue()

        except Exception, e:
            raise xmlSigDocError("Error outputting document as a string:" + \
                                 str(e))



    
    def parse(self, xmlTxt):

        """Parse string containing XML into a libxml2 document to allow
        signature validation"""

        self.__libxml2ParseDoc(xmlTxt)



    
    def read(self, filePath=None):

        """Read XML into a libxml2 document to allow signature validation"""

        # Check for file path passed as input argument otherwise use member
        # variable
        if filePath is not None:
            self.__filePath = filePath

        self.__libxml2ParseFile()




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

        Keyword arguments required by xmlSigDoc.sign():
        
        signingKeyFilePath:     file path to private key file of Attribute
                                Authority - may also be set in  __init__

        signingKeyPwd:          password for signing key file.

        certFilePathList:    file path to certificate file of Attribute
                                Authority  - may also be set in  __init__
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



    
    def createXML(self):

        """VIRTUAL method - derived class should implement -
        Create text for output and return as a string"""
        
        raise xmlSigDocError(\
                    "Virtual function: Derived class should implement.")

        return None



    
    def sign(self,
             xmlTxt=None,
             signingKeyFilePath=None,
             signingKeyPwd=None,
             certFilePathList=None,
	     inclX509Cert=True,
             inclX509SubjName=True,
	     inclX509IssSerial=True):
        """Sign XML document using an X.509 certificate and key

        xmlTxt:                 string buffer containing xml to be signed. If
                                not provided, calls xmlSigDoc.createXML().
                                This is a virtual method so must be defined
                                in a derived class.
                            
        signingKeyFilePath:     file path to private key file of Attribute
                                Authority - may also be set in  __init__

        signingKeyPwd:          password for signing key file.
        
        certFilePathList:    	file path to certificate file of Attribute
                                Authority  - may also be set in  __init__
	inclX509Cert:		include MIME encoded content of X.509 
				certificate that will sign the document
        inclX509SubjName:	include subject name of signing X.509 
				certificate.
	inclX509IssSerial:	include issuer name and serial inumber in
				signature	
        """

        # Create string buffer from virtual function if not passed
        # as input argument - derived class must implement 
        if xmlTxt is None:
            xmlTxt = self.createXML()

            
        # Attribute Authority server's private key file
        if signingKeyFilePath is not None:
            self.__signingKeyFilePath = signingKeyFilePath            


        # Attribute Authority server's RSA certificate file 
        if certFilePathList is not None:
            self.setCertFilePathList(certFilePathList)


        # Check files for read access
        try:
            if not os.access(self.__signingKeyFilePath, os.R_OK):
                raise xmlSigDocError("not found or no read access")
                                     
        except Exception, e:
            raise xmlSigDocError(\
                "Private key file path is not valid: \"%s\": %s" % \
                (self.__signingKeyFilePath, str(e)))

        
        try:
            if not os.access(self.__certFilePathList[0], os.R_OK):
                raise xmlSigDocError("not found or no read access")
            
        except Exception, e:
            raise xmlSigDocError(\
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
            raise xmlSigDocError("Error creating signature template")

        
        # Add <dsig:Signature/> node to the doc
        self.__libxml2Doc.getRootElement().addChild(sigNode)


        # Add reference
        refNode = sigNode.addReference(xmlsec.transformSha1Id(),
                                       None, None, None)
        if refNode is None:
            raise xmlSigDocError(
                "Error adding reference to signature template")


        # Add enveloped transform
        if refNode.addTransform(xmlsec.transformEnvelopedId()) is None:
            raise xmlSigDocError(\
                "Error adding enveloped transform to reference")

 
        # Add <dsig:KeyInfo/> and <dsig:X509Data/>
        keyInfoNode = sigNode.ensureKeyInfo(None)
        if keyInfoNode is None:
            raise xmlSigDocError("Error adding key info")


        x509DataNode = keyInfoNode.addX509Data()
        if x509DataNode is None:
            raise xmlSigDocError("Error adding X509Data node")


        # Add extra X509Data info
	if inclX509Cert:
            if xmlsec.addChild(x509DataNode,
			       xmlsec.NodeX509Certificate) is None:
                raise xmlSigDocError("Error adding %s node" % \
                                     xmlsec.NodeX509Certificate)

	if inclX509SubjName:
            if xmlsec.addChild(x509DataNode,
			       xmlsec.NodeX509SubjectName) is None:
                raise xmlSigDocError("Error adding %s node" % \
                                     xmlsec.NodeX509SubjectName)

	if inclX509IssSerial:
            if xmlsec.addChild(x509DataNode,
			       xmlsec.NodeX509IssuerSerial) is None:
                raise xmlSigDocError("Error adding %s node" % \
                                     xmlsec.NodeX509IssuerSerial)


        # Create signature context
        self.__xmlsecDSigCtx()

        
        # Load private key, assuming that there is not password
        self.__dSigCtxt.signKey = xmlsec.cryptoAppKeyLoad(
                                                    self.__signingKeyFilePath,
                                                    xmlsec.KeyDataFormatPem,
                                                    signingKeyPwd,
                                                    None, None)
        if self.__dSigCtxt.signKey is None:
            raise xmlSigDocError(\
                "Error loading private pem key from \"%s\"" % \
                self.__signingKeyFilePath)


        # Load certificate and add to the key
        if xmlsec.cryptoAppKeyCertLoad(self.__dSigCtxt.signKey,
                                       self.__certFilePathList[0],
                                       xmlsec.KeyDataFormatPem) < 0:
            raise xmlSigDocError("Error loading pem certificate \"%s\"" % \
                                  self.__certFilePathList[0])


        # Set key name to the file name
        if self.__dSigCtxt.signKey.setName(self.__signingKeyFilePath) < 0:
            raise xmlSigDocError(\
                "Error setting key name for key from \"%s\"" % \
                  self.__signingKeyFilePath)


        # Sign the template
        if self.__dSigCtxt.sign(sigNode) < 0:
            raise xmlSigDocError("Signature failed")




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

        certFilePathList:    Certificate used to sign the document.
                                """

        if certFilePathList is not None:
            self.setCertFilePathList(certFilePathList)

        
        # Check Certificate files for read access
        for certFilePath in self.__certFilePathList:                
            if not os.access(certFilePath, os.R_OK):
                raise xmlSigDocError(\
                    "Signing certificate file path is invalid: \"%s\": %s" % \
                                                    (certFilePath + str(e)))
            

        # Create and initialize keys manager
        self.__xmlsecKeysMngr()

        if xmlsec.cryptoAppDefaultKeysMngrInit(self.__keysMngr) < 0:
            raise xmlSigDocError("Failed to initialize keys manager.")

        
        # Load certificate(s) list should contain certificate used to sign the
        # document
        for certFilePath in self.__certFilePathList:
            if self.__keysMngr.certLoad(certFilePath,
                                        xmlsec.KeyDataFormatPem,
                                        xmlsec.KeyDataTypeTrusted) < 0:
                raise xmlSigDocError(\
                    "Error loading signing certificate \"%s\"" % certFilePath)


        # If 'xmlTxt' was input update libxml2 doc instance with it's content
        if xmlTxt is not None: self.__libxml2ParseDoc(xmlTxt)
        

        # Find start node
        dSigNode = xmlsec.findNode(self.__libxml2Doc.getRootElement(),
                                   xmlsec.NodeSignature, xmlsec.DSigNs)
        if dSigNode is None:
            raise xmlSigDocError(\
                "Start node not found in \"%s\"" % self.__filePath)

 
        # Create signature context
        self.__xmlsecDSigCtx(self.__keysMngr)


        # Verify signature
        if self.__dSigCtxt.verify(dSigNode) < 0:
            raise xmlSigDocError("Error verifying signature.")


        # Return True if signature is OK, False otherwise
        return self.__dSigCtxt.status == xmlsec.DSigStatusSucceeded




    def getKeyInfoData(self):
        """Return tags associated with KeyInfo tag of digital signature as a
        dictionary

        Call after isValidSig() or read()"""

        keyInfo = {}

        
        # Find start node
        dSigNode = xmlsec.findNode(self.__libxml2Doc.getRootElement(),
                                   xmlsec.NodeSignature, xmlsec.DSigNs)
        if dSigNode is None:
            raise xmlSigDocError(\
                "Start node not found in \"%s\"" % self.__filePath)
        
            
        keyInfoNode = xmlsec.findNode(dSigNode,
                                      xmlsec.NodeKeyInfo,
                                      xmlsec.DSigNs)
        if keyInfoNode is None:
            raise xmlSigDocError("KeyInfo node not found in \"%s\"" % \
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
