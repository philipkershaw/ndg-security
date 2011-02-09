"""XML Security ElementTree implementation

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/07/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import types
import os
import base64
from StringIO import StringIO

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
from ndg.security.common.X509 import X509CertRead, X509Stack

from ZSI.wstools.Namespaces import DSIG, XMLNS
from elementtree import ElementC14N, ElementTree

# Check ElementTree Canonicalization keywords to check if Exclusive
# Canonicalisation is set and whether an inclusive namespaces are set
isExclC14n = lambda c14nKw: bool(c14nKw.get('exclusive'))
inclNSsSet = lambda c14nKw: bool(c14nKw.get('inclusive_namespaces'))

class XMLSecDocError(Exception):
    """Exception handling for NDG XML Security class."""

class SignError(XMLSecDocError):  
    """Raised from signature method if an error occurs generating the signature
    """
     
class VerifyError(XMLSecDocError):
    """Raised from verify method if an error occurs"""
   
class InvalidSignature(XMLSecDocError):
    """Raised from verify method for an invalid signature"""

class NoSignatureFound(XMLSecDocError): 
    """Incoming message to be verified was not signed"""


#_____________________________________________________________________________
class XMLSecDoc(object):
    """Implements XML Signature and XML Encryption for a Document.
    """
    
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
        the document - see note for _setCertFilePathList() method
        @param encrPriKeyFilePath:  file path for private key used to decrypt
        previously encrypted document"""

        self._filePath = None
        self._signingKeyFilePath = None
        self._certFilePathList = None
        self._encrCertFilePath = None
        self._encrPriKeyFilePath = None
        self._rootTree = None
        self._rootElem = None

        if filePath is not None:
            self._setFilePath(filePath)

        # Private key file to be used to sign the document
        if signingKeyFilePath is not None:
            self._setSigningKeyFilePath(signingKeyFilePath)

        # Password protecting Private key used to sign the document - password
        # may be None
        self._setSigningKeyPwd(signingKeyPwd)

        # Public key file to be used to encrypt document
        if encrCertFilePath is not None:
            self._setEncrCertFilePath(encrCertFilePath)

        # Private key file to be used to decrypt document
        if encrPriKeyFilePath is not None:
            self._setEncrPriKeyFilePath(encrPriKeyFilePath)

        # This may be either of:
        # 1) Certificate file to be used for signing document
        # 2) list of certificates used to verify a signed document
        if certFilePathList is not None:
            self._setCertFilePathList(certFilePathList)
        
        
    def __str__(self):
        """String representation of doc - only applies if doc had been read
        or parsed"""
        return self.toString()
        

    def _getFilePath(self):
        """Get file path for file to be signed/encrypted."""
        return self._filePath


    def _setFilePath(self, filePath):
        """Set file path for file to be signed/verified/encrypted/decrypted
        
        @param filePath: file path of XML doc"""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError, "Document file path must be a valid string"
        
        self._filePath = filePath


    def _delFilePath(self):
        """Prevent file path being deleted."""
        raise AttributeError, "\"filePath\" cannot be deleted"
 
  
    # Publish attribute as read/write
    filePath = property(fget=_getFilePath,
                        fset=_setFilePath,
                        fdel=_delFilePath,
                        doc="File Path for XML document to apply security to")
    
    
    def _getRootElem(self):
        """Get file path for file to be signed/encrypted."""
        return self._rootElem


    def _delRootElem(self):
        """Prevent file path being deleted."""
        raise AttributeError("\"rootElem\" cannot be deleted")
 
  
    # Publish attribute as read/write
    rootElem = property(fget=_getRootElem,
                        fdel=_delRootElem,
                        doc="Root ElementTree.Element for XML")

    def _setCertFilePathList(self, filePath):
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
            self._certFilePathList = [filePath]

        elif isinstance(filePath, list):
            self._certFilePathList = filePath
                                            
        elif isinstance(filePath, tuple):
            self._certFilePathList = list(filePath)

        else:
            raise XMLSecDocError, \
            "Signing Certificate file path must be a valid string or list"
 
  
    # Publish attribute as write only
    certFilePathList = property(fset=_setCertFilePathList,
        doc="File Path of certificate used to sign document / " + \
            "list of certificates used to check the signature of a doc")


    def _setSigningKeyFilePath(self, filePath):
        """Set file path for certificate private key used to sign doc."""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError(
                "Certificate key file path must be a valid string")
        
        self._signingKeyFilePath = filePath

    # Publish attribute as write only
    signingKeyFilePath = property(fset=_setSigningKeyFilePath,
                          doc="path for private key file used to sign doc")


    def _setSigningKeyPwd(self, pwd):
        """Set password to read private key from file
        
        @param pwd: password protecting private key file - set to None if no
        password is set"""
        
        if pwd is not None and not isinstance(pwd, basestring):            
            raise XMLSecDocError(
            "Private key password must be set to None or to a valid string")
        
        self._signingKeyPwd = pwd

    # Publish attribute as write only
    signingKeyPwd = property(fset=_setSigningKeyPwd,
                doc="Password protecting private key file used to sign doc")


    def _setEncrCertFilePath(self, filePath):
        """Set file path for X.509 certificate file containing public
        key used to decrypt doc.
        
        @param filePath: path to X.509 Certificate file"""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError, \
                "Certificate key file path must be a valid string"

        self._encrCertFilePath = filePath

    # Publish attribute as write only
    encrCertFilePath = property(fset=_setEncrCertFilePath,
        doc="file path for certificate public key used to decrypt doc")


    def _setEncrPriKeyFilePath(self, filePath):
        """Set file path for private key used to decrypt doc.
        
        @param filePath: path to private key file"""
        
        if filePath is None or not isinstance(filePath, basestring):            
            raise XMLSecDocError, \
                "Certificate key file path must be a valid string"
        
        self._encrPriKeyFilePath = filePath

    # Publish attribute as write only
    encrPriKeyFilePath = property(fset=_setEncrPriKeyFilePath,
        doc="file path for certificate private key used to decrypt doc")
        
        
    def toString(self, inclXMLhdr=True):
        """Return certificate file content as a string
        
        @param inclXMLhdr: boolean - set to true to include XML header
        @return content of document as a string or None if the document has
        not been parsed."""

        if self._rootElem is None:
            return ''
        
        if inclXMLhdr:
            return '<?xml version="1.0" encoding="utf-8"?>\n' + \
                   self.canonicalize()
        else:
            return self.canonicalize()


    def parse(self, xmlTxt):
        """Parse string containing XML into a DOM to allow signature or 
        signature validation
        
        @param xmlTxt: text to be parsed"""
        fInput = StringIO()
        fInput.write(xmlTxt)
        fInput.seek(0)
        
        self._rootETree = ElementC14N.parse(fInput)
        self._rootElem = self._rootETree.getroot()
        

    fromString = parse

    def read(self, stream=None):
        """Read XML into an ElementTree document to allow signature validation
        
        @param stream: read from a file stream object instead of 
        self._filePath"""
        
        if stream is None:
            # File object or file path string may be passed to parse
            stream = self._filePath

        self._rootETree = ElementC14N.parse(stream)
        self._rootElem = self._rootETree.getroot()


    def write(self):
        """Write XML document"""
#        try:
#            f = open(self._filePath, 'w')
#        except IOError, e:
#            raise XMLSecDocError('Writing file: %s' % e)
        
        ElementC14N.write(update_scoped_tree(self._rootETree), self._filePath)#f)


    def canonicalize(self, **kw):
        '''ElementTree based Canonicalization - See ElementC14N for keyword
        info'''
        f = StringIO()
        ElementC14N.write(update_scoped_tree(self._rootETree),f,**kw)            
        c14n = f.getvalue()

        return c14n
        
        
    def applyEnvelopedSignature(self,
                                xmlTxt=None,
                                inclX509Cert=True,
                                refC14nKw={},
                                signedInfoC14nKw={}):        
        """Make enveloped signature of XML document

        @type xmlTxt: string
        @param xmlTxt: string buffer containing xml to be signed. If not 
        provided, calls XMLSecDoc.createXML().  This is a virtual method so 
        must be defined in a derived class.
          
        @type inclX509Cert: bool                  
        @param inclX509Cert: include MIME encoded content of X.509
        certificate.  This can be used by the  recipient of the XML in order 
        to verify the message
        
        @type refC14nKw: dict
        @param refC14nKw: Keywords for canonicalization of the reference
        - for enveloped type signature this is the parent element of the XML 
        document.  

        @type signedInfoC14nKw: dict
        @param signedInfoC14nKw: keywords for canonicalization of the 
        SignedInfo section of the signature.  
        """
        log.debug("XMLSecDoc.applyEnvelopedSignature ...")
        
        if xmlTxt:
            log.debug("Parsing from input string ...")
            self.parse(xmlTxt)

        if self._rootElem is None:
            raise XMLSecDocError("XML to be signed has not been read in or "
                                 "parsed.")

        # Exclusive or inclusive Canonicalization applied to Reference and 
        # SignedInfo sections?
        
        signedInfoC14nIsExcl = isExclC14n(signedInfoC14nKw)
        signedInfoC14nHasInclNSs = inclNSsSet(signedInfoC14nKw)
        log.debug("SignedInfo C14N method set to %s ..." % \
                  (signedInfoC14nIsExcl and 'exclusive' or 'inclusive'))
        
        refC14nIsExcl = isExclC14n(refC14nKw)
        refC14nHasInclNSs = inclNSsSet(refC14nKw)
        
#        parentNode.setAttributeNS(XMLNS.BASE, 'xmlns:%s' % 'ds', DSIG.BASE)
#        parentNode.setAttributeNS(XMLNS.BASE,'xmlns:%s' % 'ec',DSIG.C14N_EXCL)
        self._rootElem.set('xmlns:%s' % 'ds', DSIG.BASE)
        if refC14nIsExcl:
            log.debug("Reference C14N method set to exclusive ...")
            self._rootElem.set('xmlns:%s' % 'ec', DSIG.C14N_EXCL)
        else:
            log.debug("Reference C14N method set to inclusive ...")
            self._rootElem.set('xmlns:%s' % 'ec', DSIG.C14N)
            
        # Namespaces for XPath searches
        processorNss = {'ds': DSIG.BASE}
        if refC14nIsExcl:
            processorNss['ec'] = DSIG.C14N_EXCL


        # 1) Reference Generation
        
        # Canonicalize reference - for enveloped signature this is the parent
        # element
        refC14n = self.canonicalize(**refC14nKw)
        log.debug("Reference C14N = %s" % refC14n)
        
        # Calculate digest for reference and base 64 encode
        #
        # Nb. encodestring adds a trailing newline char
        refDigestValue = base64.encodestring(sha(refC14n).digest()).strip()


        # Add Signature elements
        signatureElem = ElementTree.SubElement(self._rootElem,
                                            "{%s}%s" % (DSIG.BASE,'Signature'))

        
        # Signature - Signed Info
        signedInfoElem = ElementTree.SubElement(signatureElem,
                                        "{%s}%s" % (DSIG.BASE,'SignedInfo'))

        
        # Signed Info - Canonicalization method
        c14nMethodElem = ElementTree.SubElement(signedInfoElem,
                                                "{%s}%s" % (DSIG.BASE,
                                                'CanonicalizationMethod'))
               
        if signedInfoC14nIsExcl:
            c14nMethodElem.set('Algorithm', DSIG.C14N_EXCL)
            if signedInfoC14nHasInclNSs:
                c14nInclNamespacesElem = ElementTree.SubElement(c14nMethodElem,
                                                "{%s}%s" % (DSIG.C14N_EXCL,
                                                'InclusiveNamespaces')) 
                  
                c14nInclNamespacesElem.setAttribute('PrefixList', 
                            ' '.join(signedInfoC14nKw['inclusive_namespaces']))        
        else:
            c14nMethodElem.set('Algorithm', DSIG.C14N)
                    
        
        # Signed Info - Signature method
        sigMethodElem = ElementTree.SubElement(signedInfoElem,
                                               "{%s}%s" % (DSIG.BASE,
                                               'SignatureMethod'))
        sigMethodElem.set('Algorithm', DSIG.SIG_RSA_SHA1)
        
        # Signature - Signature value
        signatureValueElem = ElementTree.SubElement(signatureElem,
                                                    "{%s}%s" % (DSIG.BASE, 
                                                    'SignatureValue'))
        
        # Key Info
        keyInfoElem = ElementTree.SubElement(signatureElem,
                                            "{%s}%s" % (DSIG.BASE, 'KeyInfo'))

        # Add a new reference element to SignedInfo - URI is set to null
        # indicating enveloped signature used
        refElem = ElementTree.SubElement(signedInfoElem,
                                         "{%s}%s" % (DSIG.BASE, 'Reference'))
        refElem.set('URI', "")
        
        
        # Add Transforms 
        transformsElem = ElementTree.SubElement(refElem,
                                                "{%s}%s" % (DSIG.BASE, 
                                                'Transforms'))


        # Individual transforms - enveloped digital signature
        transformElem = ElementTree.SubElement(transformsElem,
                                               "{%s}%s" % (DSIG.BASE, 
                                               'Transform'))
        transformElem.set('Algorithm', DSIG.ENVELOPED)
        
        # ... - canonicalization algorithm
        transformElem = ElementTree.SubElement(transformsElem,
                                               "{%s}%s" % (DSIG.BASE, 
                                               'Transform'))
        if refC14nIsExcl:
            transformElem.set('Algorithm', DSIG.C14N_EXCL)
            if refC14nHasInclNSs:
                inclNamespacesElem = ElementTree.SubElement(transformElem,
                                                    "{%s}%s" % (DSIG.C14N_EXCL,
                                                    'InclusiveNamespaces'))
                inclNamespacesElem.setAttribute('PrefixList',
                                ' '.join(refC14nKw['inclusive_namespaces']))
        else:
            transformElem.set('Algorithm', DSIG.C14N)
        
        # Digest Method 
        digestMethodElem = ElementTree.SubElement(refElem,
                                                  "{%s}%s" % (DSIG.BASE, 
                                                              'DigestMethod'))
        digestMethodElem.set('Algorithm', DSIG.DIGEST_SHA1)
        
        # Digest Value
        digestValueElem = ElementTree.SubElement(refElem,
                                                 "{%s}%s" % (DSIG.BASE, 
                                                             'DigestValue'))

        digestValueElem.text = refDigestValue


        # 2) Signature Generation
        signedInfoC14n = self.canonicalize(subset=signedInfoElem, 
                                           **signedInfoC14nKw)

        # Calculate digest of SignedInfo
        calcSignedInfoDigestValue = sha(signedInfoC14n).digest()
        
        # Read Private key to sign with    
        priKeyFile = BIO.File(open(self._signingKeyFilePath))
        priKeyPwdCallback = lambda *ar, **kw: self._signingKeyPwd
        priKey = RSA.load_key_bio(priKeyFile, callback=priKeyPwdCallback)
        
        # Sign using the private key and base 64 encode the result
        signatureValue = priKey.sign(calcSignedInfoDigestValue)
        b64EncSignatureValue = base64.encodestring(signatureValue).strip()

        # Add to <ds:SignatureValue>
        signatureValueElem.text = b64EncSignatureValue
        
        if inclX509Cert:
            if not len(self._certFilePathList):
                raise XMLSecDocError, \
                    "No X.509 Certificate set for inclusion in signature"
                    
            # Add X.509 cert data
            x509Cert = X509.load_cert(self._certFilePathList[0])            
            x509DataElem = ElementTree.SubElement(keyInfoElem,
                                                  "{%s}%s" % (DSIG.BASE, 
                                                              'X509Data'))
        
            x509CertElem = ElementTree.SubElement(x509DataElem,
                                                  "{%s}%s" % (DSIG.BASE, 
                                                  'X509Certificate'))
            x509CertElem.text = base64.encodestring(x509Cert.as_der())


    def verifyEnvelopedSignature(self, xmlTxt=None, raiseExcep=True):
        """Verify enveloped signature of XML document.  Raises 
        InvalidSignature exception if the signature is invalid

        @type xmlTxt: string
        @param xmlTxt: text from the XML file to be checked.  If omitted, the
        the existing parse document is used instead.
        
        @type raiseExcep: bool
        @param raiseExcep: set to True to raise a NoSignatureFound exception if
        no signature element is found, False to return to caller logging a 
        message"""
        
        log.debug("XMLSecDoc.verifyEnvelopedSignature ...")
       
        if xmlTxt:
            log.debug("Parsing from input string ...")
            self.parse(xmlTxt)
                                
        if self._rootElem is None:
            raise XMLSecDocError("Verify signature: no document has been "
                                 "parsed")

        processorNss = \
        {
            'ds':    DSIG.BASE,
            'ec':    DSIG.C14N_EXCL
        }
        signatureElems = self._rootElem.findall('.//ds:Signature', 
                                                namespaces=processorNss)
        if len(signatureElems) > 1:
            raise VerifyError('Multiple ds:Signature elements found')
        
        try:
            signatureElem = signatureElems[0]
        except:
            # Message wasn't signed
            msg = "No <ds:Signature> elements found - message not signed?"
            if raiseExcep:
                raise NoSignatureFound(msg)
            else:
                log.warning(msg)
                return
        
        # Extract all information required from the Signature node first and 
        # then remove it so that the reference digest may be calculated.  This
        # is necessary as for enveloped signature the digest was calculated 
        # prior to the addition of the Signature node
        
        # Check for canonicalization set via ds:CanonicalizationMethod -
        # Use this later as a back up in case no Canonicalization was set in 
        # the transforms elements

        c14nMethodElem = self._rootElem.find('.//ds:CanonicalizationMethod', 
                                             namespaces=processorNss)
        if c14nMethodElem is None:
            raise VerifyError("CanonicalizationMethod element not found: %s"%e)
        
        refElems = self._rootElem.findall('.//ds:Reference', 
                                          namespaces=processorNss)
        if len(refElems) != 1:
            raise VerifyError("Expecting one reference element for enveloped "
                              "signature")
        
        refElem = refElems[0]
        
        # Check for reference URI set to "" 
        # TODO: Nb. also allows for no ref URI set at all.  IS this OK with 
        # XMLSec Spec.
        refURI = refElem.get('URI')
        if refURI:
            raise VerifyError("Reference URI value is expected to be null for "
                              "enveloped type signature")
        
        
        # Get transforms that were applied
        transformElems = refElem.findall("ds:Transforms/ds:Transform",
                                         namespaces=processorNss)
        if transformElems == []:
            raise VerifyError('Failed to find transform elements')
            
        # Check for enveloped style signature and also check for list of 
        # namespaces to be excluded if Exclusive canonicalization method was
        # specified
        refC14nKw = {}
        envelopedAlgorithmSet = False
        
        for transformElem in transformElems:
            refAlgorithm = transformElem.get('Algorithm')
            
            if refAlgorithm == DSIG.C14N_EXCL:
                refC14nKw['exclusive'] = True
                inclusiveNsElem = transformElem.find("InclusiveNamespaces",
                                                     namespaces=processorNss)
                if inclusiveNsElem is not None:
                    pfxListAttrVal = inclusiveNsElem.get('PrefixList')
                    refC14nKw['inclusive_namespaces'] = pfxListAttrVal.split()

            elif refAlgorithm == DSIG.ENVELOPED:
                envelopedAlgorithmSet = True
       
        
        if not envelopedAlgorithmSet:
            raise VerifyError("Expecting enveloped type signature to be "
                              "specified in transform")
        
        
        # Extract the digest value for the reference 
          
        refDigestElem = refElem.find('ds:DigestValue', namespaces=processorNss)
        if refDigestElem is None:
            raise VerifyError("Error reading reference digest value")

        refDigestValue = str(refDigestElem.text).strip()

        signedInfoElems = self._rootElem.findall('.//ds:SignedInfo',
                                                 namespaces=processorNss)
        nSignedInfoElems = len(signedInfoElems)
        if nSignedInfoElems > 1:
            raise VerifyError("Multiple <ds:SignedInfo/> elements found")
        elif nSignedInfoElems == 0:
            raise VerifyError("No <ds:SignedInfo/> element found")

        signedInfoElem = signedInfoElems[0]
        
        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        signedInfoC14nAlg = c14nMethodElem.get("Algorithm")
        if signedInfoC14nAlg is None:
            raise VerifyError("No SignedInfo Algorithm attribute found")
        
        signedInfoC14nKw = {}
        if signedInfoC14nAlg == DSIG.C14N_EXCL:
            signedInfoC14nKw['exclusive'] = True
            inclusiveNsElem = c14nMethodElem.find("InclusiveNamespaces",
                                                  namespaces=processorNss)
            if inclusiveNsElem is not None:
                pfxListAttrVal = inclusiveNsElem.get('PrefixList')
                signedInfoC14nKw['inclusive_namespaces']=pfxListAttrVal.split()

        
        # Get the signature value in order to check against the digest just
        # calculated
        signatureValueElem = self._rootElem.find('.//ds:SignatureValue',
                                                 namespaces=processorNss)
        if signatureValueElem is None:
            raise VerifyError("Error reading signatureValue: %s" % e)
        
        # Remove base 64 encoding
        b64EncSignatureValue = str(signatureValueElem.text).strip()                                
        signatureValue = base64.decodestring(b64EncSignatureValue)

        # Canonicalize the SignedInfo node and take digest
        signedInfoC14n = self.canonicalize(subset=signedInfoElem, 
                                           **signedInfoC14nKw)        
        calcSignedInfoDigestValue = sha(signedInfoC14n).digest()

        # Try extracting X.509 Cert from ds:X509Certificate node in KeyInfo
        x509CertElem = self._rootElem.find('.//ds:X509Certificate',
                                           namespaces=processorNss)
        if x509CertElem is None:
            log.info("No <ds:X509Certificate/> element found for signature "
                     "verification: loading cert from 1st file in "
                     "_certFilePathList")
            m2X509Cert = X509.load_cert(self._certFilePathList[0])
        else:
            # Get certificate from <ds:X509Certificate/>
            # - Remove base 64 encoding
            derString = base64.decodestring(x509CertElem.text)
            
            # Load from DER format into M2Crypto.X509
            m2X509Cert=X509.load_cert_string(derString, format=X509.FORMAT_DER)


        # Temporarily remove the Signature node in order to correctly
        # canonicalize the reference
        self._rootElem.remove(signatureElem)
        
        
        # Two stage process: reference validation followed by signature 
        # validation 
        
        # 1) Reference Validation
        #
        # With the Signature node now removed, the parent node can now be
        # canonicalized and the digest calculated
        refC14n = self.canonicalize(**refC14nKw)
        log.debug("Reference C14N = %s" % refC14n)
        calcRefDigestValue = base64.encodestring(sha(refC14n).digest()).strip()
               
        # Restore signature node
        self._rootElem.append(signatureElem)
        
        # Reference validates if the newly calculated digest value and the 
        # digest value extracted from the Reference section of the SignedInfo 
        # are the same
        if calcRefDigestValue != refDigestValue:
            raise InvalidSignature('Digest Values do not match for reference '
                                   'data')

        # 2) Signature Validation
        #        
        # Extract RSA public key from the cert
        rsaPubKey = m2X509Cert.get_pubkey().get_rsa()

        # Compare digest value of the SignedInfo element calculated earlier 
        # against the signatureValue read from the SignedInfo
        try:
            verify = rsaPubKey.verify(calcSignedInfoDigestValue,signatureValue)
        except RSA.RSAError, e:
            raise VerifyError("Error in Signature: " + str(e))
        
        if not verify:
            raise InvalidSignature("Invalid signature")

        # Verify chain of trust if list cert list is present
        if self._certFilePathList:
            # Make a stack object for CA certs 
            caX509Stack = X509Stack()
            for cert in self._certFilePathList:
                caX509Stack.push(X509CertRead(cert))
             
            # Make a stack object for certs to be verified   
            x509Stack = X509Stack()
            x509Stack.push(m2X509Cert)
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
        omitted the file set by self._filePath is read instead.
                                
        @param inclX509SubjName: include subject name of signing X.509 
        certificate.
        
        @param inclX509IssSerial: include issuer name and serial number in
        signature"""
        
        raise NotImplementedError, \
                        "Encryption algorithm not implemented in this version"
 
    def decrypt(self, 
                xmlTxt=None, 
                filePath=None):
        """Decrypt a document using a private key of public/private key pair
        
        @param xmlTxt: string buffer containing the text from the XML file to
         be decrypted.  If omitted, the filePath argument is used instead.

        @param filePath: file path to XML file to be decrypted.  This
        argument is used if no xmlTxt was provided.  If filePath itself is 
        omitted the file set by self._filePath is read instead."""
        
        raise NotImplementedError, \
                        "Encryption algorithm not implemented in this version"

def update_scoped_tree(root):
    '''Modification of build_scoped_tree to enable updates to be made on 
    existing _scope attribute passed in the input tree.  Nb. the input is 
    an ElementTree type and NOT an Element type'''
    
    elem = root.getroot()
    
    # build scope map - may not have previously been created.
    if not hasattr(root, '_scope'):
        root._scope = {}
        
    for e in elem.getiterator():
        scope = []
        for k in e.keys():
            if k.startswith("xmlns:"):
                # move xmlns prefix to scope map
                scope.append((k[6:], e.get(k)))

        if scope:
            # Append to existing scope if it already exists
            if e in root._scope:
                # Ensure only new items are added
                uniq=[(k,v) for k,v in scope if k not in dict(root._scope[e])]
                root._scope[e] += uniq
            else:
                root._scope[e] = scope

    # build parent map
    root._parent = dict((c, p) for p in elem.getiterator() for c in p)

    return root
