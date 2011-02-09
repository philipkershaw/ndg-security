"""NDG XML Security - Encryption and Digital Signature

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/04/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'


import types
import os

# For removal of BEGIN and END CERTIFICATE markers from X.509 certs
import re

# Include for re-parsing doc ready for canonicalization in sign method - see
# associated note
from xml.dom.ext.reader.PyExpat import Reader
from Ft.Xml.Domlette import NonvalidatingReader

# Use to find parent node when parsing docs
from xml.dom.Element import Element

getParentNode = lambda docNode: [elem for elem in docNode.childNodes \
                                 if isinstance(elem, Element)][0]

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
from ndg.security.common.X509 import X509CertRead, X509Stack
import base64

# Canonicalization
from ZSI.wstools.c14n import Canonicalize
from xml.dom import Node
from xml.xpath.Context import Context
from xml import xpath

from ZSI.wstools.Namespaces import DSIG, XMLNS

    
def getElements(node, nameList):
    '''DOM Helper function for getting child elements from a given node'''
    # Avoid sub-string matches
    nameList = isinstance(nameList, basestring) and [nameList] or nameList
    return [n for n in node.childNodes if str(n.localName) in nameList]


class XMLSecDocError(Exception):
    """Exception handling for NDG XML Security class."""

class SignError(XMLSecDocError):  
    """Raised from sign method if an error occurs generating the signature"""
     
class VerifyError(XMLSecDocError):
    """Raised from verify method if an error occurs"""
   
class InvalidSignature(XMLSecDocError):
    """Raised from verify method for an invalid signature"""


class XMLSecDoc(object):
    """Implements XML Signature and XML Encryption for a Document.
    
    @type __beginCert: string
    @param __beginCert: delimiter for beginning of base64 encoded portion of
    a PEM encoded X.509 certificate
    @type __endCert: string
    @cvar: __endCert: equivalent end delimiter
    
    @type __x509CertPat: regular expression pattern object
    @cvar __x509CertPat: regular expression for extracting the base64 encoded 
    portion of a PEM encoded X.509 certificate"""
    
    __beginCert = '-----BEGIN CERTIFICATE-----\n'
    __endCert = '\n-----END CERTIFICATE-----'
    __x509CertPat = re.compile(__beginCert + \
                               '?(.*?)\n?-----END CERTIFICATE-----',
                               re.S)

    def __init__(self,
                 filePath=None,
                 signingKeyFilePath=None,
                 signingKeyPwd=None,
                 certFilePathList=None,
                 encrCertFilePath=None,
                 encrPriKeyFilePath=None):

        """Initialisation -
            
        @param filePath:            file path for document
        @param signingKeyFilePath:  file path for private key used in 
        signature
        @param certFilePathList:    list of certificates used in verification 
        of a signed document
        @param encrCertFilePath:    file path for X.509 cert used to encrypt
        the document - see note for __setCertFilePathList() method
        @param encrPriKeyFilePath:  file path for private key used to decrypt
        previously encrypted document"""

        self.__filePath = None
        self.__signingKeyFilePath = None
        self.__certFilePathList = None
        self.__encrCertFilePath = None
        self.__encrPriKeyFilePath = None
        self.__docNode = None


        if filePath is not None:
            self.__setFilePath(filePath)

        # Private key file to be used to sign the document
        if signingKeyFilePath is not None:
            self.__setSigningKeyFilePath(signingKeyFilePath)

        # Password proetcting Private key used to sign the document - password
        # may be None
        self.__setSigningKeyPwd(signingKeyPwd)

        # Public key file to be used to encrypt document
        if encrCertFilePath is not None:
            self.__setEncrCertFilePath(encrCertFilePath)

        # Private key file to be used to decrypt document
        if encrPriKeyFilePath is not None:
            self.__setEncrPriKeyFilePath(encrPriKeyFilePath)

        # This may be either of:
        # 1) Certificate file to be used for signing document
        # 2) list of certificates used to verify a signed document
        if certFilePathList is not None:
            self.__setCertFilePathList(certFilePathList)
        
        
    def __str__(self):
        """String representation of doc - only applies if doc had been read
        or parsed"""
        return self.toString()
        

    def __getFilePath(self):
        """Get file path for file to be signed/encrypted."""
        return self.__filePath


    def __setFilePath(self, filePath):
        """Set file path for file to be signed/verified/encrypted/decrypted
        
        @param filePath: file path of XML doc"""
        
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
    
    
    def __getDocNode(self):
        """Get file path for file to be signed/encrypted."""
        return self.__docNode


    def __delDocNode(self):
        """Prevent file path being deleted."""
        raise AttributeError("\"docNode\" cannot be deleted")
 
  
    # Publish attribute as read/write
    docNode = property(fget=__getDocNode,
                       fdel=__delDocNode,
                       doc="DOM document node for XML")


    def __getCertFilePathList(self):
        """@rtype: list
        @return: list of certificates used in digital signature
        """
        return self.__certFilePathList
    
    def __setCertFilePathList(self, filePath):
        """File path for certificate used to sign document / 
        list of certificates used to check the signature of a document
        
        @param filePath: file path or list of file paths to files used to
        verify a signature.  The first element should be the cert 
        corresponding to the proviate key used to make the signature.  
        Successive certs in the list correspond to the chain of trust e.g.
        if a proxy cert/private key was used the list would be
        
        proxy cert., 
        user cert which issued the proxy cert, 
        CA cert that issued the user cert
        """
        
        if isinstance(filePath, basestring):        
            self.__certFilePathList = [filePath]

        elif isinstance(filePath, list):
            self.__certFilePathList = filePath
                                            
        elif isinstance(filePath, tuple):
            self.__certFilePathList = list(filePath)

        else:
            raise XMLSecDocError("Signing Certificate file path must be a "
                                 "valid string or list")
 
  
    # Publish attribute as write only
    certFilePathList = property(fget=__getCertFilePathList,
                                fset=__setCertFilePathList,
                                doc="File Path of certificate used to sign "
                                    "document / list of certificates used to "
                                    "check the signature of a doc")


    def __setSigningKeyFilePath(self, filePath):
        """Set file path for certificate private key used to sign doc."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(
                "Certificate key file path must be a valid string")
        
        self.__signingKeyFilePath = filePath

    # Publish attribute as write only
    signingKeyFilePath = property(fset=__setSigningKeyFilePath,
                          doc="path for private key file used to sign doc")


    def __setSigningKeyPwd(self, pwd):
        """Set password to read private key from file
        
        @param pwd: password protecting private key file - set to None if no
        password is set"""
        
        if pwd is not None and not isinstance(pwd, basestring):            
            raise XMLSecDocError(
            "Private key password must be set to None or to a valid string")
        
        self.__signingKeyPwd = pwd

    # Publish attribute as write only
    signingKeyPwd = property(fset=__setSigningKeyPwd,
                doc="Password protecting private key file used to sign doc")


    def __setEncrCertFilePath(self, filePath):
        """Set file path for X.509 certificate file containing public
        key used to decrypt doc.
        
        @param filePath: path to X.509 Certificate file"""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(
                "Certificate key file path must be a valid string")

        self.__encrCertFilePath = filePath

    # Publish attribute as write only
    encrCertFilePath = property(fset=__setEncrCertFilePath,
        doc="file path for certificate publiv key used to decrypt doc")


    def __setEncrPriKeyFilePath(self, filePath):
        """Set file path for private key used to decrypt doc.
        
        @param filePath: path to private key file"""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(
                "Certificate key file path must be a valid string")
        
        self.__encrPriKeyFilePath = filePath

    # Publish attribute as write only
    encrPriKeyFilePath = property(fset=__setEncrPriKeyFilePath,
        doc="file path for certificate private key used to decrypt doc")


    def toString(self, inclXMLhdr=True):
        """Return certificate file content as a string
        
        @param inclXMLhdr: boolean - set to true to include XML header
        @return content of document as a string or None if the document has
        not been parsed."""

        if not self.__docNode:
            return None
        
        if inclXMLhdr:
            return '<?xml version="1.0" encoding="utf-8"?>\n' + \
                    Canonicalize(self.__docNode)
        else:
            return Canonicalize(self.__docNode)


    def parse(self, xmlTxt):
        """Parse string containing XML into a DOM to allow signature or 
        signature validation
        
        @param xmlTxt: text to be parsed"""
        
        self.__docNode = Reader().fromString(xmlTxt)


    def read(self, stream=None):
        """Read XML into a document to allow signature validation
        
        @param stream: read from a file stream object instead of 
        self.__filePath"""
        
        if stream is None:
            stream = open(self.__filePath)
                
        self.__docNode = Reader().fromStream(stream)


    def write(self):
        """Write XML document"""
        open(self.__filePath, 'w').write(self.toString() + os.linesep)


    def applyEnvelopedSignature(self,
                        xmlTxt=None,
                        inclX509Cert=True,
                        refC14nKw={'unsuppressedPrefixes': ['xmlns']},
                        signedInfoC14nKw={'unsuppressedPrefixes': ['ds']}):
        
        """Make enveloped signature of XML document

        @param xmlTxt: string buffer containing xml to be signed. If not 
        provided, calls XMLSecDoc.createXML().  This is a virtual method so 
        must be defined in a derived class.
                            
        @param inclX509Cert: include MIME encoded content of X.509
        certificate.  This can be used by the  recipient of the XML in order 
        to verify the message
        
        @param refC14nKw: Keywords for canonicalization of the reference
        - for enveloped type signature this is the parent element of the XML 
        document.  If the key 'unsuppressedPrefixes' is set to a list of 
        element prefix strings, exclusive canonicalization will be applied.  
        To use inclusive canonicalization set 'unsuppressedPrefixes' to None
         or set refC14nKw to None.
         
        @param signedInfoC14nKw: keywords for canonicalization of the 
        SignedInfo section of the signature.  See explanation for refC14nKw
        keyword for options."""

        if xmlTxt:
            self.parse(xmlTxt)

        if self.__docNode is None:
            raise XMLSecDocError(
                            "XML to be signed has not been read in or parsed.")

        try:
            parentNode = getParentNode(self.__docNode)
        except Exception, e:
            raise SignError("Locating parent node: " + str(e))

        parentNode.setAttributeNS(XMLNS.BASE, 'xmlns:%s' % 'ds', DSIG.BASE)
        parentNode.setAttributeNS(XMLNS.BASE,'xmlns:%s' % 'ec',DSIG.C14N_EXCL)
        
        # Namespaces for XPath searches
        processorNss = \
        {
            'ds':    DSIG.BASE,
            'ec':    DSIG.C14N_EXCL
        }
        ctx = Context(self.__docNode, processorNss=processorNss)
        
        # 1) Reference Generation
        
        # Canonicalize reference - for enveloped signature this is the parent
        # element
        refC14n = Canonicalize(parentNode, **refC14nKw)
        
        # Calculate digest for reference and base 64 encode
        #
        # Nb. encodestring adds a trailing newline char
        refDigestValue = base64.encodestring(sha(refC14n).digest()).strip()


        # Add Signature elements
        signatureNode = self.__docNode.createElementNS(DSIG.BASE,
                                                       'ds:Signature')
        parentNode.appendChild(signatureNode)

        
        # Signature - Signed Info
        signedInfoNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                        'ds:SignedInfo')
        signatureNode.appendChild(signedInfoNode)
        
        # Signed Info - Canonicalization method
        c14nMethodNode = self.__docNode.createElementNS(DSIG.BASE,
                                                'ds:CanonicalizationMethod')        
        c14nMethodNode.setAttribute('Algorithm', DSIG.C14N_EXCL)
        signedInfoNode.appendChild(c14nMethodNode)

        c14nInclNamespacesNode = self.__docNode.createElementNS(\
                                                     DSIG.C14N_EXCL,
                                                     'ec:InclusiveNamespaces')       
        c14nInclNamespacesNode.setAttribute('PrefixList', 
                        ' '.join(signedInfoC14nKw['unsuppressedPrefixes']))        
        c14nMethodNode.appendChild(c14nInclNamespacesNode)
        
        
        # Signed Info - Signature method
        sigMethodNode = self.__docNode.createElementNS(DSIG.BASE,
                                                       'ds:SignatureMethod')
        sigMethodNode.setAttribute('Algorithm', DSIG.SIG_RSA_SHA1)
        signedInfoNode.appendChild(sigMethodNode)
        
        # Signature - Signature value
        signatureValueNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                        'ds:SignatureValue')
        signatureNode.appendChild(signatureValueNode)
        
        
        # Key Info
        keyInfoNode = self.__docNode.createElementNS(DSIG.BASE, 'ds:KeyInfo')
        signatureNode.appendChild(keyInfoNode)


        # Add a new reference element to SignedInfo - URI is set to null
        # indicating enveloped signature used
        refNode = self.__docNode.createElementNS(DSIG.BASE, 'ds:Reference')
        refNode.setAttribute('URI', "")
        signedInfoNode.appendChild(refNode)
        
        
        # Add Transforms 
        transformsNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                        'ds:Transforms')
        refNode.appendChild(transformsNode)

        # Individual transforms - enveloped digital signature
        transformNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                       'ds:Transform')
        transformNode.setAttribute('Algorithm', DSIG.ENVELOPED)
        transformsNode.appendChild(transformNode)
        
        # ... - exclusive canonicalization
        transformNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                       'ds:Transform')
        transformNode.setAttribute('Algorithm', DSIG.C14N_EXCL)
        transformsNode.appendChild(transformNode)
        
        inclNamespacesNode = self.__docNode.createElementNS(\
                                                   DSIG.C14N_EXCL,
                                                   'ec:InclusiveNamespaces')
        inclNamespacesNode.setAttribute('PrefixList',
                                ' '.join(refC14nKw['unsuppressedPrefixes']))
        transformNode.appendChild(inclNamespacesNode)
        
        
        # Digest Method 
        digestMethodNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                          'ds:DigestMethod')
        digestMethodNode.setAttribute('Algorithm', DSIG.DIGEST_SHA1)
        refNode.appendChild(digestMethodNode)
        
        # Digest Value
        digestValueNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                         'ds:DigestValue')
        refNode.appendChild(digestValueNode)
        
        digestValueTxtNode = self.__docNode.createTextNode(refDigestValue)
        digestValueNode.appendChild(digestValueTxtNode)


        # 2) Signature Generation
        signedInfoC14n = Canonicalize(signedInfoNode, **signedInfoC14nKw)

        # Calculate digest of SignedInfo
        calcSignedInfoDigestValue = sha(signedInfoC14n).digest()
        
        # Read Private key to sign with    
        priKeyFile = BIO.File(open(self.__signingKeyFilePath))
        priKeyPwdCallback = lambda *ar, **kw: self.__signingKeyPwd
        priKey = RSA.load_key_bio(priKeyFile, callback=priKeyPwdCallback)
        
        # Sign using the private key and base 64 encode the result
        signatureValue = priKey.sign(calcSignedInfoDigestValue)
        b64EncSignatureValue = base64.encodestring(signatureValue).strip()

        # Add to <ds:SignatureValue>
        signatureValueTxtNode = \
                        self.__docNode.createTextNode(b64EncSignatureValue)
        signatureValueNode.appendChild(signatureValueTxtNode)
        
        
        if inclX509Cert:
            if not len(self.__certFilePathList):
                raise XMLSecDocError(
                    "No X.509 Certificate set for inclusion in signature")
                    
            # Add X.509 cert data
            x509Cert = X509.load_cert(self.__certFilePathList[0])            
            x509DataNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                          'ds:X509Data')
            keyInfoNode.appendChild(x509DataNode)
            
        
            x509CertNode = self.__docNode.createElementNS(DSIG.BASE, 
                                                      'ds:X509Certificate')
            x509DataNode.appendChild(x509CertNode)

            x509CertPat = re.compile(\
            '-----BEGIN CERTIFICATE-----\n?(.*?)\n?-----END CERTIFICATE-----',
            re.S)
            x509CertStr = x509CertPat.findall(x509Cert.as_pem())[0]
                
            x509CertTxtNode = self.__docNode.createTextNode(x509CertStr)
            x509CertNode.appendChild(x509CertTxtNode)


    def verifyEnvelopedSignature(self, xmlTxt=None):
        """Verify enveloped signature of XML document.  Raises 
        InvalidSignature exception if the signature is invalid

        @type xmlTxt: string
        @param xmlTxt: text from the XML file to be checked.  If omitted, the
        the existing parse document is used instead."""
       
        if xmlTxt:
            self.parse(xmlTxt)
                                
        if self.__docNode is None:
            raise XMLSecDocError(
                            "verify signature: no document has been parsed")

        try:
            parentNode = getParentNode(self.__docNode)
        except Exception, e:
            raise VerifyError("Locating parent node: " + str(e))
        
        processorNss = \
        {
            'ds':    DSIG.BASE,
            'ec':    DSIG.C14N_EXCL
        }
        ctx = Context(self.__docNode, processorNss=processorNss)
        

        signatureNodes = xpath.Evaluate('//ds:Signature', 
                                        contextNode=self.__docNode, 
                                        context=ctx)
        if len(signatureNodes) > 1:
            raise VerifyError('Multiple ds:Signature elements found')
        
        try:
            signatureNode = signatureNodes[0]
        except:
            # Message wasn't signed
            return
        
        # Extract all information required from the Signature node first and 
        # then remove it so that the reference digest may be calculated.  This
        # is necessary as for enveloped signature the digest was calculated 
        # prior to the addition of the Signature node
        
        # Check for canonicalization set via ds:CanonicalizationMethod -
        # Use this later as a back up in case no Canonicalization was set in 
        # the transforms elements
        try:
            c14nMethodNode = xpath.Evaluate('//ds:CanonicalizationMethod', 
                                            contextNode=self.__docNode, 
                                            context=ctx)[0]
        except Exception, e:
            raise VerifyError("CanonicalizationMethod element not found: " +
                                str(e))
        
        refNodes = xpath.Evaluate('//ds:Reference', 
                                  contextNode=self.__docNode, 
                                  context=ctx)
        if len(refNodes) != 1:
            raise VerifyError(
                    "Expecting one reference element for enveloped signature")
        
        refNode = refNodes[0]
        
        # Check for reference URI set
        refURIattrNode = refNode.getAttributeNode('URI')
        if refURIattrNode and refURIattrNode.value:
            raise VerifyError("Reference URI value is expected to be "
                               "null for enveloped type signature")
        
        
        # Get transforms that were applied
        try:
            tfmsNode = getElements(refNode, "Transforms")[0]
            tfmNodes = getElements(tfmsNode, "Transform")

        except Exception, e:
            raise VerifyError,'failed to get transform algorithm: %s' % str(e)
            
            
        # Check for enveloped style signature and also check for list of 
        # namespaces to be excluded if Exclusive canonicalization method was
        # specified
        refC14nKw = {}
        envelopedAlgorithmSet = False
        
        try:
            for tfmNode in tfmNodes:
                refAlgorithm = tfmNode.getAttributeNode('Algorithm').value
                
                if refAlgorithm == DSIG.C14N_EXCL:
                        inclusiveNSnode = getElements(tfmNode, 
                                                  "InclusiveNamespaces")[0]
                        
                        pfxListAttNode = inclusiveNSnode.getAttributeNode(\
                                                               'PrefixList')
                        refC14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
                        break
                elif refAlgorithm == DSIG.ENVELOPED:
                    envelopedAlgorithmSet = True
        except Exception, e:
            raise VerifyError('Failed to parse tranform node: %s' % e)
       
        
        if not envelopedAlgorithmSet:
            raise VerifyError(
            "Expecting enveloped type signature to be specified in transform")
        
        
        # Extract the digest value for the reference 
        try:           
            refDigestNode = getElements(refNode, "DigestValue")[0]
            refDigestValue=str(refDigestNode.childNodes[0].nodeValue).strip()
            
        except Exception, e:
            raise VerifyError("Error reading reference digest value")
        

        try:
            signedInfoNode = xpath.Evaluate('//ds:SignedInfo',
                                            contextNode=self.__docNode, 
                                            context=ctx)[0]
        except Exception, e:
            raise VerifyError("Error reading SignedInfo element: " + str(e))


        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        try:
            signedInfoC14nAlg = c14nMethodNode.getAttributeNode(\
                                                            "Algorithm").value
            signedInfoC14nKw = {}
            if signedInfoC14nAlg == DSIG.C14N_EXCL:
                inclusiveNS = getElements(c14nMethodNode,
                                          "InclusiveNamespaces")
                
                pfxListAttNode = inclusiveNS[0].getAttributeNode('PrefixList')
                signedInfoC14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
        except Exception, e:
            raise VerifyError('failed to handle exclusive '
                              'canonicalisation for SignedInfo: %s' % e)
        
        # Get the signature value in order to check against the digest just
        # calculated
        try:
            signatureValueNode = xpath.Evaluate('//ds:SignatureValue',
                                                contextNode=self.__docNode, 
                                                context=ctx)[0]    
            # Remove base 64 encoding
            b64EncSignatureValue = \
                    str(signatureValueNode.childNodes[0].nodeValue).strip()
        except Exception, e:
            raise VerifyError("Error reading signatureValue: " + str(e))
                    
        signatureValue = base64.decodestring(b64EncSignatureValue)

        # Canonicalize the SignedInfo node and take digest
        signedInfoC14n = Canonicalize(signedInfoNode, **signedInfoC14nKw)        
        calcSignedInfoDigestValue = sha(signedInfoC14n).digest()

        try:
            # Try extracting X.509 Cert from ds:X509Certificate node in 
            # KeyInfo
            x509CertNode = xpath.Evaluate('//ds:X509Certificate',
                                          contextNode=self.__docNode,
                                          context=ctx)[0]
            b64EncX509Cert = self.__class__.__beginCert + \
                         str(x509CertNode.childNodes[0]._get_nodeValue()) + \
                         self.__class__.__endCert

            x509Cert = X509.load_cert_string(b64EncX509Cert)
            
        except Exception, e:
            raise VerifyError(
                'Unable to read certificate from "ds:X509Certificate" element')


        # Temporarily remove the Signature node in order to correctly
        # canonicalize the reference
        signatureNode = parentNode.removeChild(signatureNode)
        
        
        # Two stage process: reference validation followed by signature 
        # validation 
        
        # 1) Reference Validation
        #
        # With the Signature node now removed, the parent node can now be
        # canonicalized and the digest calculated
        refC14n = Canonicalize(parentNode, **refC14nKw)
        calcDigestValue = base64.encodestring(sha(refC14n).digest()).strip()
        
        # Restore signature node
        parentNode.appendChild(signatureNode)
        
        
        # Reference validates if the newly calculated digest value and the 
        # digest value extracted from the Reference section of the SignedInfo 
        # are the same
        if calcDigestValue != refDigestValue:
            raise InvalidSignature, \
                            'Digest Values do not match for reference data'


        # 2) Signature Validation
        #        
        # Extract RSA public key from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()


        # Compare digest value of the SignedInfo element calculated earlier 
        # against the signatureValue read from the SignedInfo
        try:
            verify = rsaPubKey.verify(calcSignedInfoDigestValue, 
                                      signatureValue)
        except RSA.RSAError, e:
            raise VerifyError("Error in Signature: " + str(e))
        
        if not verify:
            raise InvalidSignature, "Invalid signature"
        
        # Verify chain of trust if list cert list is present
        if self.__certFilePathList:
            # Make a stack object for CA certs 
            caX509Stack = X509Stack()
            for cert in self.__certFilePathList:
                caX509Stack.push(X509CertRead(cert))
             
            # Make a stack object for certs to be verified   
            x509Stack = X509Stack()
            x509Stack.push(x509Cert)
            x509Stack.verifyCertChain(caX509Stack=caX509Stack)


    def encrypt(self,
                xmlTxt=None, 
                filePath=None, 
                inclX509SubjName=True,
                inclX509IssSerial=True):
        """Encrypt a document using recipient's public key

        Encrypts xml file using a dynamically created template, a session 
        triple DES key and an RSA key from keys manager.
        
        @param xmlTxt: string buffer containing the text from the XML file to 
        be encrypted.  If omitted, the filePath argument is used instead.

        @param filePath: file path to XML file to be encrypted.  This
        argument is used if no xmlTxt was provided.  If filePath itself is 
        omitted the file set by self.__filePath is read instead.
                                
        @param inclX509SubjName: include subject name of signing X.509 
        certificate.
        
        @param inclX509IssSerial: include issuer name and serial number in
        signature"""
        
        raise NotImplementedError(
                        "Encryption algorithm not implemented in this version")
 
 
    def decrypt(self, 
                xmlTxt=None, 
                filePath=None):
        """Decrypt a document using a private key of public/private key pair
        
        @param xmlTxt: string buffer containing the text from the XML file to
         be decrypted.  If omitted, the filePath argument is used instead.

        @param filePath: file path to XML file to be decrypted.  This
        argument is used if no xmlTxt was provided.  If filePath itself is 
        omitted the file set by self.__filePath is read instead."""
        
        raise NotImplementedError(
                        "Encryption algorithm not implemented in this version")
