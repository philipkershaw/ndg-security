"""WS-Security digital signature handler for ElementTree XML package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/07/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import base64
import os
import re

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
from StringIO import StringIO

from ZSI.wstools.Namespaces import DSIG, SOAP

from elementtree import ElementTree, ElementC14N

# Check SoapWriter.dom attribute is ElementTreeProxy type
from ndg.security.common.zsi.elementtreeproxy import ElementTreeProxy

from ndg.security.common.wssecurity import WSSecurityError
from ndg.security.common.wssecurity.signaturehandler import _WSU, OASIS, \
    BaseSignatureHandler, NoSignatureFound, \
    InvalidSignature, TimestampError, MessageExpired, VerifyError, \
    SignatureError


from ndg.security.common.X509 import X509Cert, X509CertParse, X509CertRead, \
X509Stack, X509StackParseFromDER

from datetime import datetime, timedelta

# Workaround for lack of datetime.strptime in Python < 2.5
if hasattr(datetime, 'strptime'):
    _strptime = datetime.strptime
else:
    from time import strptime
    _strptime = lambda datetimeStr, format: datetime(*(strptime(datetimeStr, 
                                                                format)[0:6]))
import logging
log = logging.getLogger(__name__)

class SignatureHandler(BaseSignatureHandler):
    """Class to handle signature and verification of signature with 
    WS-Security
    """

    # Namespaces for XPath searches
    _processorNSs = \
    {
        'ds':       DSIG.BASE, 
        'wsu':      _WSU.UTILITY, 
        'wsse':     OASIS.WSSE, 
        'SOAP-ENV': SOAP.ENV 
    }


    def _applySignatureConfirmation(self, wsseElem):
        '''Add SignatureConfirmation element - as specified in WS-Security 1.1
        - to outbound message on receipt of a signed message from a client
        
        This has been added in through tests vs. Apache Axis Rampart client
        
        @type wsseElem: 
        @param wsseElem: wsse:Security element'''
        if self.b64EncSignatureValue is None:
            log.info("SignatureConfirmation element requested but no request "
                     "signature was cached")
            return
        
        sigConfirmElem = ElementTree.Element("{%s}%s" % (OASIS.WSSE11, 
                                                      'SignatureConfirmation'))
        wsseElem.append(sigConfirmElem)
        
        # Add ID so that the element can be included in the signature
        sigConfirmElem.set('{%s}Id' % _WSU.UTILITY, "signatureConfirmation")

        # Add ID so that the element can be included in the signature
        # Following line is a hack to avoid appearance of #x when serialising 
        # \n chars 
        # TODO: Fix #x problem with sig value?
        b64EncSignatureValue = ''.join(self.b64EncSignatureValue.split('\n'))
        sigConfirmElem.set('Value', b64EncSignatureValue)
        
        
    def _addTimeStamp(self, wsseElem, elapsedSec=60*5):
        '''Add a timestamp to wsse:Security section of message to be signed
        e.g.
            <wsu:Timestamp wsu:Id="timestamp">
               <wsu:Created>2008-03-25T14:40:37.319Z</wsu:Created>
               <wsu:Expires>2008-03-25T14:45:37.319Z</wsu:Expires>
            </wsu:Timestamp>
        
        @type wsseElem: 
        @param wsseElem: wsse:Security element
        @type elapsedSec: int    
        @param elapsedSec: time interval in seconds between Created and Expires
        time stamp values 
        '''
        # Nb. wsu ns declaration is in the SOAP header elem
        timestampElem=ElementTree.Element("{%s}%s"%(_WSU.UTILITY,'Timestamp'))
        wsseElem.append(timestampElem)
        
        # Add ID so that the timestamp element can be included in the signature
        timestampElem.set('{%s}Id' % _WSU.UTILITY, "timestamp")
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        createdElem = ElementTree.Element("{%s}%s" % (_WSU.UTILITY,'Created'))
        timestampElem.append(createdElem)
        
        dtCreatedTime = datetime.utcnow()
        createdElem.text = dtCreatedTime.isoformat('T') + 'Z'
        
        dtExpiryTime = dtCreatedTime + timedelta(seconds=elapsedSec)
        expiresElem = ElementTree.Element("{%s}%s" % (_WSU.UTILITY, 'Expires'))
        timestampElem.append(expiresElem)
        
        expiresElem.text = dtExpiryTime.isoformat('T') + 'Z'
        

    def _verifyTimeStamp(self, 
                         parsedSOAP, 
                         timestampMustBeSet=False,
                         createdElemMustBeSet=True,
                         expiresElemMustBeSet=True):
        """Call from verify to check timestamp if found.  
        
        TODO: refactor input args - maybe these should by object attributes
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender
        @type timestampMustBeSet: bool
        @type timestampMustBeSet: bool
        @param timestampMustBeSet: if set to True, raise an exception if no
        timestamp element is found
        @type createdElemMustBeSet: bool
        @param createdElemMustBeSet: if True. raise an exception if no
        <wsu:Created/> element is present
        @param expiresElemMustBeSet: if True. raise an exception if no
        <wsu:Expires/> element is present
        """
        timestampElems = self._soapEnvElem.findall('.//wsu:Timestamp', 
                                                namespaces=self._processorNSs)
        nTimestampElems = len(timestampElems)        
        if nTimestampElems > 1:
            raise TimestampError("Expecting only one timestamp element")
        
        elif nTimestampElems == 0:
            msg = "Verifying message - No timestamp element found"
            if timestampMustBeSet:
                raise VerifyError(msg)
            else:
                log.warning(msg)
                return
        
        timestampElem = timestampElems[0]
        
        # Time now 
        dtNow = datetime.utcnow()
        
        createdElem = timestampElem.find("wsu:Created", 
                                         namespaces=self._processorNSs)
        if createdElem is None:
            "No <wsu:Created/> element found in timestamp"
            if createdElemMustBeSet:
                raise TimestampError(msg)
            else:
                log.warning(msg)
        else:
            # Workaround for fractions of second with datetime module
            try:
                createdDateTime, strCreatedSecFraction = \
                                                    createdElem.text.split('.')
                strCreatedSecFraction = strCreatedSecFraction.split('Z')[0]
                createdExp = -int(len(strCreatedSecFraction))
                createdSecFraction = int(strCreatedSecFraction) *10**createdExp
                
            except ValueError, e:
                raise ValueError("Parsing timestamp Created element: %s" % e)
            
    
            dtCreated = _strptime(createdDateTime, '%Y-%m-%dT%H:%M:%S')
            dtCreated += timedelta(seconds=createdSecFraction)
            if dtCreated >= dtNow:
                raise TimestampError("Timestamp created time %s is equal to "
                                     "or after the current time %s" %
                                     (dtCreated, dtNow))
        
        expiresElem = timestampElem.find("wsu:Expires",
                                         namespaces=self._processorNSs)
        if expiresElem is None:
            msg = "No <wsu:Expires/> element found in Timestamp"
            if expiresElemMustBeSet:
                raise TimestampError(msg)
            else:
                log.warning(msg)
        else:
            try:
                expiryDateTime, strExpirySecFraction = \
                                                    expiresElem.text.split('.')
                strExpirySecFraction = strExpirySecFraction.split('Z')[0]
                expiryExp = -int(len(strExpirySecFraction))
                expirySecFraction = int(strExpirySecFraction) * 10 ** expiryExp
                
            except ValueError, e:
                raise ValueError("Parsing timestamp Expires element: %s" % e)
            
            dtExpiry = _strptime(expiryDateTime, '%Y-%m-%dT%H:%M:%S')
            dtExpiry += timedelta(seconds=expirySecFraction)
            if dtExpiry < dtNow:
                raise MessageExpired("Message has expired: timestamp expiry "
                                     "time %s is before the current time %s" % 
                                     (dtCreated, dtNow))
            
        log.debug("Completed timestamp verification")
            
            
    def sign(self, soapWriter):
        '''Sign the message body and binary security token of a SOAP message
        
        @type soapWriter: ZSI.writer.SoapWriter
        @param soapWriter: ZSI object to write SOAP message
        '''
        
        # Check for expected soapWriter DOM class
        if not isinstance(soapWriter.dom, ElementTreeProxy):
            raise SignatureError("Expecting ElementTreeProxy type for "
                                 "ZSI.writer.SoapWriter.dom instance")
            
        # Add X.509 cert as binary security token
        # TODO: sub encodestring with b64encode?
        if self.reqBinSecTokValType==self.binSecTokValType['X509PKIPathv1']:
            binSecTokVal = base64.encodestring(self.signingCertChain.asDER())
        else:
            # Assume X.509 / X.509 vers 3
            binSecTokVal = base64.encodestring(self.signingCert.asDER())

        self._soapEnvElem = soapWriter.dom._elem
        soapHdrElem = soapWriter._header._elem
        soapBodyElem = soapWriter.body._elem
        
        self._soapEnvElem.set("xmlns:%s" % 'ds', DSIG.BASE)
        #self._soapEnvElem.set("xmlns:%s" % 'wsse', OASIS.WSSE)
        
        soapHdrElem.set("xmlns:%s" % 'wsse', OASIS.WSSE)
        soapHdrElem.set("xmlns:%s" % 'wsse11', OASIS.WSSE11)
#        soapHdrElem.set("xmlns:%s" % 'wsu', _WSU.UTILITY)
        self._soapEnvElem.set("xmlns:%s" % 'wsu', _WSU.UTILITY)
        soapHdrElem.set("xmlns:%s" % 'ds', DSIG.BASE)
        
        refC14nPfxSet = False
        if isinstance(self.refC14nKw.get('inclusive_namespaces'), list) and \
            len(self.refC14nKw['inclusive_namespaces']) > 0:
            refC14nPfxSet = True 

        signedInfoC14nPfxSet = False
        if isinstance(self.signedInfoC14nKw.get('inclusive_namespaces'), list) and \
            len(self.signedInfoC14nKw['inclusive_namespaces']) > 0:
            signedInfoC14nPfxSet = True
                
        if refC14nPfxSet or signedInfoC14nPfxSet:
            soapHdrElem.set("xmlns:%s" % 'ec', DSIG.C14N_EXCL)
            
            
        # Check <wsse:security> isn't already present in header
        wsseElems = self._soapEnvElem.findall('.//wsse:security',
                                              namespaces=self._processorNSs)
        if len(wsseElems) > 1:
            raise SignatureError('wsse:Security element is already present')
        
        # Add WSSE element
        wsseElem = ElementTree.Element("{%s}%s" % (OASIS.WSSE, 'Security'))
        soapHdrElem.append(wsseElem)
        
        wsseElem.set("xmlns:%s" % 'wsse', OASIS.WSSE)
        
        # Recipient MUST parse and check this signature 
        wsseElem.set('SOAP-ENV:mustUnderstand', "1")
        
        # Binary Security Token element will contain the X.509 cert 
        # corresponding to the private key used to sing the message
        binSecTokElem = ElementTree.Element("{%s}%s" % (OASIS.WSSE, 
                                                        'BinarySecurityToken'))
        wsseElem.append(binSecTokElem)
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        binSecTokElem.set('ValueType', self.reqBinSecTokValType)
        binSecTokElem.set('EncodingType', self._binSecTokEncType)
        
        # Add ID so that the binary token can be included in the signature
        binSecTokElem.set('{%s}Id' % _WSU.UTILITY, "binaryToken")
        
        binSecTokElem.text = binSecTokVal


        # Timestamp
        if self.addTimestamp:
            self._addTimeStamp(wsseElem)
            
        # Signature Confirmation
        if self.applySignatureConfirmation: 
            self._applySignatureConfirmation(wsseElem)
        
        # Signature
        signatureElem = ElementTree.Element("{%s}%s" % (DSIG.BASE,'Signature'))
        wsseElem.append(signatureElem)
        
        # Signature - Signed Info
        signedInfoElem = ElementTree.Element("{%s}%s"%(DSIG.BASE,'SignedInfo'))
        signatureElem.append(signedInfoElem)
        
        # Signed Info - Canonicalization method
        c14nMethodElem = ElementTree.Element("{%s}%s" % (DSIG.BASE,
                                                    'CanonicalizationMethod'))
        signedInfoElem.append(c14nMethodElem)
        
        # Set based on 'signedInfoIsExcl' property
        c14nAlgOpt = (DSIG.C14N, DSIG.C14N_EXCL)
        signedInfoC14nAlg = c14nAlgOpt[int(self.signedInfoC14nIsExcl)]
        
        c14nMethodElem.set('Algorithm', signedInfoC14nAlg)
        
        if signedInfoC14nPfxSet:
            c14nInclNamespacesElem = ElementTree.Element("{%s}%s" % \
                                                    (signedInfoC14nAlg,
                                                    'InclusiveNamespaces'))
            c14nMethodElem.append(c14nInclNamespacesElem)
            
            pfxList = ' '.join(self.signedInfoC14nKw['inclusive_namespaces'])
            c14nInclNamespacesElem.set('PrefixList', pfxList)

        
        # Signed Info - Signature method
        sigMethodElem = ElementTree.Element("{%s}%s" % \
                                            (DSIG.BASE, 'SignatureMethod'))
        signedInfoElem.append(sigMethodElem)
        sigMethodElem.set('Algorithm', DSIG.SIG_RSA_SHA1)
        
        # Signature - Signature value
        signatureValueElem = ElementTree.Element("{%s}%s" % (DSIG.BASE, 
                                                             'SignatureValue'))
        signatureElem.append(signatureValueElem)
        
        # Key Info
        KeyInfoElem = ElementTree.Element("{%s}%s" % (DSIG.BASE, 'KeyInfo'))
        signatureElem.append(KeyInfoElem)
        
        secTokRefElem = ElementTree.Element("{%s}%s" % (OASIS.WSSE, 
                                                    'SecurityTokenReference'))
        KeyInfoElem.append(secTokRefElem)
        
        # Reference back to the binary token included earlier
        wsseRefElem = ElementTree.Element("{%s}%s" % (OASIS.WSSE, 'Reference'))
        secTokRefElem.append(wsseRefElem)
        
        wsseRefElem.set('URI', "#binaryToken")
        
        # Add Reference to body so that it can be included in the signature
        #soapBodyElem.set('xmlns:wsu', _WSU.UTILITY) - results in duplicate xmlns declarations
        soapBodyElem.set('{%s}Id' % _WSU.UTILITY, 'body')


        # Set Reference Canonicalization algorithm based on 'refC14nIsExcl' 
        # property
        refC14nAlg = c14nAlgOpt[self.refC14nIsExcl]
        
        # Pick up all the wsu:Id tagged elements set in the above
        refElems = self._soapEnvElem.findall('.//*[@wsu:Id]',
                                             namespaces=self._processorNSs)

        # 1) Reference Generation
        #
        # Find references
        for refElem in refElems:
            
            # Set URI attribute to point to reference to be signed
            uri = '#' + refElem.get('{%s}%s' % (_WSU.UTILITY, 'Id'))
            
            # Canonicalize reference
            refC14n = soapWriter.dom.canonicalize(subset=refElem,
                                                  exclusive=self.refC14nIsExcl,
                                                  **self.refC14nKw)
            log.debug('Canonicalisation for URI "%s": %s', uri, refC14n)
            
            # Calculate digest for reference and base 64 encode
            #
            # Nb. encodestring adds a trailing newline char
            # Use b64encode instead - encodestring puts in newline chars at
            # 76 char intervals
            #digestValue = base64.encodestring(sha(refC14n).digest()).strip()
            digestValue = base64.b64encode(sha(refC14n).digest())
            
            # Add a new reference element to SignedInfo
            signedInfoRefElem = ElementTree.Element("{%s}Reference"%DSIG.BASE)
            signedInfoElem.append(signedInfoRefElem)
            signedInfoRefElem.set('URI', uri)
            
            # Use ds:Transforms or wsse:TransformationParameters?
            transformsElem = ElementTree.Element("{%s}Transforms" % DSIG.BASE)
            signedInfoRefElem.append(transformsElem)
            
            transformElem = ElementTree.Element("{%s}Transform" % DSIG.BASE)
            transformsElem.append(transformElem)

            # Set Canonicalization algorithm type
            transformElem.set('Algorithm', refC14nAlg)
            if refC14nPfxSet:
                # Exclusive C14N requires inclusive namespace elements
                inclNamespacesElem = transformElem.createAppendElement(\
                                                       refC14nAlg,
                                                       'InclusiveNamespaces')
                refPfxList = ' '.join(self.refC14nKw['inclusive_namespaces'])
                inclNamespacesElem.set('PrefixList', refPfxList)
            
            # Digest Method 
            digestMethodElem = ElementTree.Element("{%s}%s" % (DSIG.BASE, 
                                                               'DigestMethod'))
            signedInfoRefElem.append(digestMethodElem)
            
            digestMethodElem.set('Algorithm', DSIG.DIGEST_SHA1)
            
            # Digest Value
            digestValueElem = ElementTree.Element("{%s}%s" % (DSIG.BASE, 
                                                              'DigestValue'))
            signedInfoRefElem.append(digestValueElem)
            digestValueElem.text = digestValue
   
        # 2) Signature Generation
        #        
        # Canonicalize the signedInfo node
        c14nSignedInfo = soapWriter.dom.canonicalize(subset=signedInfoElem,
                                           exclusive=self.signedInfoC14nIsExcl,
                                           **self.signedInfoC14nKw)
        log.debug('Canonicalisation for <ds:signedInfo>: %s', c14nSignedInfo)
        
        # Calculate digest of SignedInfo
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Sign using the private key and base 64 encode the result
        signatureValue = self.signingPriKey.sign(signedInfoDigestValue)
        
        # encodestring puts newline markers at 76 char intervals otherwise no 
        # difference
        # b64EncSignatureValue = base64.encodestring(signatureValue).strip()
        b64EncSignatureValue = base64.b64encode(signatureValue)

        # Add to <SignatureValue>
        signatureValueElem.text = b64EncSignatureValue
        log.debug("Signature generation complete")


    def verify(self, parsedSOAP):
        """Verify signature
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender"""

        if not isinstance(parsedSOAP.dom, ElementTreeProxy):
            raise VerifyError("Expecting ElementTreeProxy type for "
                              "ZSI.parse.ParsedSoap.dom")
        
        self._soapEnvElem = parsedSOAP.dom._elem

        signatureElems = self._soapEnvElem.findall('.//ds:Signature', 
                                                namespaces=self._processorNSs)        
        if len(signatureElems) > 1:
            raise VerifyError('Multiple <ds:Signature/> elements found')
        
        try:
            signatureElems = signatureElems[0]
        except:
            # Message wasn't signed - may be possible if peer raised a SOAP
            # fault
            raise NoSignatureFound("Input message wasn't signed!")

        
        # Two stage process: reference validation followed by signature 
        # validation 
        
        # 1) Reference Validation
        
        # Check for canonicalization set via ds:CanonicalizationMethod -
        # Use this later as a back up in case no Canonicalization was set in 
        # the transforms elements
        c14nMethodElem = self._soapEnvElem.find('.//ds:CanonicalizationMethod', 
                                                namespaces=self._processorNSs)
        if c14nMethodElem is None:
            raise VerifyError("No <ds:Canonicalization/> element found")  
             
        refElems = self._soapEnvElem.findall('.//ds:Reference', 
                                             namespaces=self._processorNSs)
        if len(refElems) == 0:
            raise VerifyError("No <ds:Reference/> elements found")  
        
        for refElem in refElems:
            # Get the URI for the reference
            refURI = refElem.get('URI')
                         
            transformElem = refElem.find('ds:Transforms/ds:Transform',
                                         namespaces=self._processorNSs)
            if transformElem is None:
                raise VerifyError('Failed to get transform algorithm for '
                                  '<ds:Reference URI="%s">' % refURI)
                
            refAlgorithm = transformElem.get("Algorithm")
                
            # Add extra keyword for Exclusive canonicalization method
            refC14nKw = dict(exclusive=refAlgorithm == DSIG.C14N_EXCL)
            if refC14nKw['exclusive']:
                # Check for no inclusive namespaces set
                inclusiveNSElem = transformElem.find("InclusiveNamespaces",
                                                namespaces=self._processorNSs)                    
                if inclusiveNSElem is not None:
                    pfxListTxt = inclusiveNSElem.get('PrefixList')
                    if pfxListTxt is None:
                        raise VerifyError('Empty InclusiveNamespaces list for'\
                                          ' <ds:Reference URI="%s">' % refURI)
                                                  
                    refC14nKw['inclusive_namespaces'] = pfxListTxt.split()
                else:
                    # Set to empty list to ensure Exclusive C14N is set for
                    # Canonicalize call
                    refC14nKw['inclusive_namespaces'] = []
        
            # Canonicalize the reference data and calculate the digest
            if refURI[0] != "#":
                raise VerifyError('Expecting # identifier for Reference URI' \
                                  ' "%s"' % refURI)
                    
            # XPath reference
            uriXPath = './/*[@wsu:Id="%s"]' % refURI[1:]
            uriElem=self._soapEnvElem.findall(uriXPath,
                                              namespaces=self._processorNSs)
            if len(uriElem) > 1:
                raise VerifyError("Multiple elements matching '%s' search" 
                                  " path: %s" % (uriXPath, uriElem))

            refC14n=parsedSOAP.dom.canonicalize(subset=uriElem[0], **refC14nKw)
            
            # encodestring adds line delimiters at 76 char intervals - avoid 
            # and use b64encode instead            
            calculatedDigestValue = base64.b64encode(sha(refC14n).digest())
            
            # Extract the digest value that was stored in the SOAP request         
            digestElem = refElem.find('ds:DigestValue',
                                      namespaces=self._processorNSs)
            if digestElem is None:
                raise VerifyError('Failed to get digestValue for ' \
                                  '<ds:Reference URI="%s">' % refURI)
                
            # Need to check here for value split into separate lines?
            retrievedDigestValue = str(digestElem.text).strip()   
            
            # Reference validates if the two digest values are the same
            if retrievedDigestValue != calculatedDigestValue:
                log.error("Digest values don't match")
                log.error('Canonicalisation for URI: "%s": %s' % \
                          (refURI, refC14n))
                raise InvalidSignature('Digest Values do not match for URI:' \
                                       ' "%s"' % refURI)
            
            log.debug("Verified canonicalization for element '%s'"%refURI[1:])
            

        # 2) Signature Validation
        signedInfoElem = self._soapEnvElem.find('.//ds:SignedInfo',
                                                namespaces=self._processorNSs)
        if signedInfoElem is None:
            raise VerifyError("No <ds:signedInfo/> section found")
        
        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        signedInfoC14nAlg = c14nMethodElem.get("Algorithm")
        if signedInfoC14nAlg is None:
            raise VerifyError('No Algorithm attribute set for <signedInfo/>' \
                              ' section')
            
        signedInfoC14nKw = dict(exclusive=signedInfoC14nAlg == DSIG.C14N_EXCL)
        if signedInfoC14nKw['exclusive']:

            # Check for no inclusive namespaces set
            inclusiveNSElem = c14nMethodElem.find("InclusiveNamespaces",
                                                namespaces=self._processorNSs)                    
            if inclusiveNSElem is not None:
                pfxListTxt = inclusiveNSElem.get('PrefixList')
                if pfxListTxt is None:
                    raise VerifyError('Empty InclusiveNamespaces list for'\
                                      ' <ds:Reference URI="%s">' % refURI)
                                              
                signedInfoC14nKw['inclusive_namespaces'] = pfxListTxt.split()
            else:
                # Set to empty list to ensure Exclusive C14N is set for
                # Canonicalize call
                signedInfoC14nKw['inclusive_namespaces'] = []

        # Canonicalize the SignedInfo node and take digest
        c14nSignedInfo = parsedSOAP.dom.canonicalize(subset=signedInfoElem, 
                                                     **signedInfoC14nKw)                      
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Get the signature value in order to check against the digest just
        # calculated
        signatureValueElem = self._soapEnvElem.find('.//ds:SignatureValue',
                                                namespaces=self._processorNSs)

        # Remove base 64 encoding
        b64EncSignatureValue = signatureValueElem.text
        signatureValue = base64.decodestring(b64EncSignatureValue)

        # Cache Signature Value here so that a response can include it
        if self.applySignatureConfirmation:
            # re-encode string to avoid possible problems with interpretation 
            # of line breaks
            self.b64EncSignatureValue = b64EncSignatureValue
        else:
            self.b64EncSignatureValue = None
         
        # Look for X.509 Cert in wsse:BinarySecurityToken element - 
        # Signature may not have included the Binary Security Token in 
        # which case the verifying cert will need to have been set 
        # elsewhere
        binSecTokElem = self._soapEnvElem.find('.//wsse:BinarySecurityToken',
                                               namespaces=self._processorNSs)        
        if binSecTokElem is not None:
            x509CertTxt = str(binSecTokElem.text)
            
            valueType = binSecTokElem.get("ValueType")
            if valueType in (self.binSecTokValType['X509v3'],
                             self.binSecTokValType['X509']):
                # Remove base 64 encoding
                derString = base64.decodestring(x509CertTxt)
                self.verifyingCert = X509Cert.Parse(derString, 
                                                    format=X509Cert.formatDER)
                
                x509Stack = X509Stack()

            elif valueType == self.binSecTokValType['X509PKIPathv1']:
                
                derString = base64.decodestring(x509CertTxt)
                x509Stack = X509StackParseFromDER(derString)
                
                # TODO: Check ordering - is the last off the stack the
                # one to use to verify the message?
                self.verifyingCert = x509Stack[-1]
            else:
                raise WSSecurityError('BinarySecurityToken ValueType '
                                      'attribute is not recognised: "%s"' % 
                                      valueType)

        if self.verifyingCert is None:
            raise VerifyError("No certificate set for verification of the "
                              "signature")
        
        # Extract RSA public key from the cert
        rsaPubKey = self.verifyingCert.pubKey.get_rsa()

        # Apply the signature verification
        try:
            verify = rsaPubKey.verify(signedInfoDigestValue, signatureValue)
        except RSA.RSAError, e:
            raise VerifyError("Error in Signature: " + str(e))
        
        if not verify:
            raise InvalidSignature("Invalid signature")
        
        log.debug("Verified signature")
        
        # Verify chain of trust 
        x509Stack.verifyCertChain(x509Cert2Verify=self.verifyingCert,
                                  caX509Stack=self.__caX509Stack)

        log.debug("Verified certificate chain of trust")
        
        self._verifyTimeStamp(parsedSOAP,
                              timestampMustBeSet=self.timestampMustBeSet,
                              createdElemMustBeSet=self.createdElemMustBeSet,
                              expiresElemMustBeSet=self.expiresElemMustBeSet) 

        log.info("Signature OK")        


    def canonicalize(self, **kw):
        '''ElementTree based Canonicalization - See ElementC14N for keyword
        info'''
        f = StringIO()
        ElementC14N.write(ElementC14N.build_scoped_tree(self._soapEnvElem), 
                          f, 
                          **kw)
        return f.getvalue()