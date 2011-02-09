"""4Suite XML based WS-Security digital signature handler

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/02/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

import os
import re
from cStringIO import StringIO

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
import base64
from datetime import datetime, timedelta

# Workaround for lack of datetime.strptime in Python < 2.5
if hasattr(datetime, 'strptime'):
    _strptime = datetime.strptime
else:
    from time import strptime
    _strptime = lambda datetimeStr, format: datetime(*(strptime(datetimeStr, 
                                                                format)[0:6]))
    
from ZSI.wstools.Namespaces import DSIG, SOAP

# Canonicalization
from Ft.Xml.Domlette import CanonicalPrint

from ndg.security.common.wssecurity import WSSecurityError
from ndg.security.common.wssecurity.signaturehandler import _WSU, OASIS, \
    BaseSignatureHandler, NoSignatureFound, InvalidSignature, TimestampError, \
    MessageExpired, VerifyError, SignatureError

from ndg.security.common.X509 import X509Cert, X509CertParse, X509CertRead, \
    X509Stack, X509StackParseFromDER


def getElements(node, nameList):
    '''DOM Helper function for getting child elements from a given node'''
    # Avoid sub-string matches
    nameList = isinstance(nameList, basestring) and [nameList] or nameList
    return [n for n in node.childNodes if str(n.localName) in nameList]


class SignatureHandler(BaseSignatureHandler):
    """Class to handle signature and verification of signature with 
    WS-Security
    """

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
        
        sigConfirmElem = wsseElem.createAppendElement(OASIS.WSSE11, 
                                                      'SignatureConfirmation')
        
        # Add ID so that the element can be included in the signature
        sigConfirmElem.setAttributeNS(_WSU.UTILITY, 
                                      'Id', 
                                      'signatureConfirmation')
        
        # Add ID so that the element can be included in the signature
        # Following line is a hck to avoid appearance of #x when serialising \n
        # chars TODO: why is this happening??
        b64EncSignatureValue = ''.join(self.b64EncSignatureValue.split('\n'))
        sigConfirmElem.setAttributeNS(None, 'Value', b64EncSignatureValue)
        
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
        timestampElem = wsseElem.createAppendElement(_WSU.UTILITY, 'Timestamp')

        # Add ID so that the timestamp element can be included in the signature
        timestampElem.setAttributeNS(_WSU.UTILITY, 'Id', "timestamp")
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        createdElem = timestampElem.createAppendElement(_WSU.UTILITY,'Created')
        dtCreatedTime = datetime.utcnow()
        createdElem.createAppendTextNode(dtCreatedTime.isoformat('T')+'Z')
        
        dtExpiryTime = dtCreatedTime + timedelta(seconds=elapsedSec)
        expiresElem = timestampElem.createAppendElement(_WSU.UTILITY,'Expires')
        expiresElem.createAppendTextNode(dtExpiryTime.isoformat('T')+'Z')
        

    def _verifyTimeStamp(self, 
                         parsedSOAP, 
                         processorNss,
                         timestampClockSkew=0.,
                         timestampMustBeSet=False,
                         createdElemMustBeSet=True,
                         expiresElemMustBeSet=True):
        """Call from verify to check timestamp if found.  The WS-Security 1.1
        specification allows elements to be optional.  Hence, the bool flags
        enable their configuration.  The default behaviour is, send a warning
        if a timestamp is not found but if a timestamp is present raise
        an exception if the created or the expired elements are missing.
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender
        @type processorNss: dict
        @param processorNss: namespaces to be used in XPath query to locate
        timestamp.
        @type timestampClockSkew: int/float
        @param timestampClockSkew: adjust the current time calculated by the 
        number of seconds specified in this parameter.  This enables allowance
        to be made for clock skew between a client and server system clocks. 
        @type timestampMustBeSet: bool
        @param timestampMustBeSet: if set to True, raise an exception if no
        timestamp element is found
        @type createdElemMustBeSet: bool
        @param createdElemMustBeSet: if True. raise an exception if no
        <wsu:Created/> element is present
        @param expiresElemMustBeSet: if True. raise an exception if no
        <wsu:Expires/> element is present
        """

        try:
            timestampElem = parsedSOAP.dom.xpath('//wsu:Timestamp', 
                                                 explicitNss=processorNss)[0]
        except IndexError:
            # Catch TypeError raised from attempt to reference element 0 of
            # None type
            msg = "Verifying message - No timestamp element found"
            if timestampMustBeSet:
                raise TimestampError(msg)
            else:
                log.warning(msg)
                return
        
        # Time now 
        dtNow = datetime.utcnow() + timedelta(seconds=timestampClockSkew)

        createdElem = getElements(timestampElem, "Created")           
        if len(createdElem) == 0:
            msg = ("Verifying message: no <wsu:Created/> timestamp "
                   "sub-element found")
            if createdElemMustBeSet:
                raise TimestampError(msg)
            else:
                log.warning(msg)
        else:               
            # Workaround for fractions of second
            try:
                createdDateTime, createdSecFraction = \
                            createdElem[0].childNodes[0].nodeValue.split('.')
                dtCreated = _strptime(createdDateTime, '%Y-%m-%dT%H:%M:%S')
                createdSeconds = float("0."+createdSecFraction.replace('Z',''))
                dtCreated += timedelta(seconds=createdSeconds)
                                                
            except ValueError, e:
                raise TimestampError("Failed to parse timestamp Created "
                                     "element: %s" % e)
            
            if dtCreated >= dtNow:
                raise TimestampError("Timestamp created time %s is equal to "
                                     "or after the current time %s" %
                                     (dtCreated, dtNow))
        
        expiresElem = getElements(timestampElem, "Expires")
        if len(expiresElem) == 0:
            msg = ("Verifying message: no <wsu:Expires/> element found in "
                   "Timestamp")
            if expiresElemMustBeSet:
                raise TimeStampError(msg)
            else:
                log.warning(warning)
        else:
            try:
                expiresDateTime, expiresSecFraction = \
                            expiresElem[0].childNodes[0].nodeValue.split('.')
                dtExpiry = _strptime(expiresDateTime, '%Y-%m-%dT%H:%M:%S')
                expirySeconds = float("0."+expiresSecFraction.replace('Z', ''))
                dtExpiry += timedelta(seconds=expirySeconds)
    
            except ValueError, e:
                raise TimestampError("Failed to parse timestamp Expires "
                                     "element: %s" % e)
    
            if dtExpiry < dtNow:
                raise MessageExpired("Message has expired: timestamp expiry "
                                     "time %s is before the current time %s." %
                                     (dtExpiry, dtNow))
            
                   
    def sign(self, soapWriter):
        '''Sign the message body and binary security token of a SOAP message
        
        @type soapWriter: ZSI.writer.SoapWriter
        @param soapWriter: ZSI object to write SOAP message
        '''
        
        # Namespaces for XPath searches
        processorNss = \
        {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }

        # Add X.509 cert as binary security token
        if self.reqBinSecTokValType==self.binSecTokValType['X509PKIPathv1']:
            if self.signingCertChain is None:
                msg = 'SignatureHandler signingCertChain attribute is not set'
                log.error(msg)
                raise AttributeError(msg)
            
            binSecTokVal = base64.encodestring(self.signingCertChain.asDER())
        else:
            # Assume X.509 / X.509 vers 3
            if self.signingCert is None:
                msg = 'SignatureHandler signingCert attribute is not set'
                log.error(msg)
                raise AttributeError(msg)
            
            binSecTokVal = base64.encodestring(self.signingCert.asDER())

        soapWriter._header.setNamespaceAttribute('wsse', OASIS.WSSE)
        soapWriter._header.setNamespaceAttribute('wsse11', OASIS.WSSE11)
        soapWriter._header.setNamespaceAttribute('wsu', _WSU.UTILITY)
        soapWriter._header.setNamespaceAttribute('ds', DSIG.BASE)
        
        # Flag if inclusive namespace prefixes are set for the signature or
        # reference elements
        refC14nPfxSet = len(self.refC14nKw['inclusive_namespaces']) > 0
        signedInfoC14nPfxSet = \
                        len(self.signedInfoC14nKw['inclusive_namespaces']) > 0
                
        if refC14nPfxSet or signedInfoC14nPfxSet:
           soapWriter._header.setNamespaceAttribute('ec', DSIG.C14N_EXCL)
        
        # Check <wsse:security> isn't already present in header
        wsseElems = soapWriter._header.evaluate('//wsse:security', 
                                                processorNss=processorNss)
        if len(wsseElems) > 1:
            raise SignatureError('wsse:Security element is already present')

        # Add WSSE element
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                          'Security')
        wsseElem.setNamespaceAttribute('wsse', OASIS.WSSE)
        
        # Flag to recipient - they MUST parse and check this signature 
        wsseElem.setAttributeNS(SOAP.ENV, 'mustUnderstand', "1")
        
        # Binary Security Token element will contain the X.509 cert 
        # corresponding to the private key used to sing the message
        binSecTokElem = wsseElem.createAppendElement(OASIS.WSSE, 
                                                     'BinarySecurityToken')
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        binSecTokElem.setAttributeNS(None, 
                                     'ValueType', 
                                     self.reqBinSecTokValType)

        binSecTokElem.setAttributeNS(None, 
                                     'EncodingType',
                                     self._binSecTokEncType)
        
        # Add ID so that the binary token can be included in the signature
        binSecTokElem.setAttributeNS(_WSU.UTILITY, 'Id', "binaryToken")

        binSecTokElem.createAppendTextNode(binSecTokVal)

        # Timestamp
        if self.addTimestamp:
            self._addTimeStamp(wsseElem)
            
        # Signature Confirmation
        if self.applySignatureConfirmation: 
            self._applySignatureConfirmation(wsseElem)
        
        # Signature
        signatureElem = wsseElem.createAppendElement(DSIG.BASE, 'Signature')
        signatureElem.setNamespaceAttribute('ds', DSIG.BASE)
        
        # Signature - Signed Info
        signedInfoElem = signatureElem.createAppendElement(DSIG.BASE, 
                                                           'SignedInfo')
        
        # Signed Info - Canonicalization method
        c14nMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                    'CanonicalizationMethod')
        
        # Set based on 'signedInfoIsExcl' property
        c14nAlgOpt = (DSIG.C14N, DSIG.C14N_EXCL)
        signedInfoC14nAlg = c14nAlgOpt[int(self.signedInfoC14nIsExcl)]
        
        c14nMethodElem.setAttributeNS(None, 'Algorithm', signedInfoC14nAlg)
        
        if signedInfoC14nPfxSet:
            c14nInclNamespacesElem = c14nMethodElem.createAppendElement(
                                                    signedInfoC14nAlg,
                                                    'InclusiveNamespaces')
            inclNsPfx = ' '.join(self.signedInfoC14nKw['inclusive_namespaces'])
            c14nInclNamespacesElem.setAttributeNS(None,'PrefixList',inclNsPfx)
        
        # Signed Info - Signature method
        sigMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                           'SignatureMethod')
        sigMethodElem.setAttributeNS(None, 'Algorithm', DSIG.SIG_RSA_SHA1)
        
        # Signature - Signature value
        signatureValueElem = signatureElem.createAppendElement(DSIG.BASE, 
                                                             'SignatureValue')
        
        # Key Info
        KeyInfoElem = signatureElem.createAppendElement(DSIG.BASE, 'KeyInfo')
        secTokRefElem = KeyInfoElem.createAppendElement(OASIS.WSSE, 
                                                  'SecurityTokenReference')
        
        # Reference back to the binary token included earlier
        wsseRefElem = secTokRefElem.createAppendElement(OASIS.WSSE, 
                                                        'Reference')
        wsseRefElem.setAttributeNS(None, 'URI', "#binaryToken")
        
        # Add Reference to body so that it can be included in the signature
        soapWriter.body.setAttributeNS(_WSU.UTILITY, 'Id', "body")

        refElems = soapWriter.body.evaluate('//*[@wsu:Id]', 
                                            processorNss=processorNss)
        
        # Set based on 'signedInfoIsExcl' property
        refC14nAlg = c14nAlgOpt[int(self.refC14nIsExcl)]
        
        # 1) Reference Generation
        #
        # Find references
        for refElem in refElems:
            
            refID = refElem.getAttributeValue(_WSU.UTILITY, 'Id')
            
            # Set URI attribute to point to reference to be signed
            uri = u"#" + refID
            
            # Canonicalize reference
            inclusiveNsKWs = self.createUnsupressedPrefixKW(self.refC14nKw)
            refC14n = refElem.canonicalize(algorithm=refC14nAlg, 
                                           **inclusiveNsKWs)

            # Calculate digest for reference and base 64 encode
            #
            # Nb. encodestring adds a trailing newline char
            digestValue = base64.encodestring(sha(refC14n).digest()).strip()


            # Add a new reference element to SignedInfo
            refElem = signedInfoElem.createAppendElement(DSIG.BASE, 
                                                         'Reference')
            refElem.setAttributeNS(None, 'URI', uri)
            
            # Use ds:Transforms or wsse:TransformationParameters?
            transformsElem = refElem.createAppendElement(DSIG.BASE, 
                                                         'Transforms')
            transformElem = transformsElem.createAppendElement(DSIG.BASE, 
                                                               'Transform')

            # Set Canonicalization algorithm type
            transformElem.setAttributeNS(None, 'Algorithm', refC14nAlg)
            if refC14nPfxSet:
                # Exclusive C14N requires inclusive namespace elements
                inclNamespacesElem = transformElem.createAppendElement(
							                           refC14nAlg,
                                                       'InclusiveNamespaces')
                refInclNsPfx = ' '.join(self.refC14nKw['inclusive_namespaces'])
                inclNamespacesElem.setAttributeNS(None, 'PrefixList', 
                                                  refInclNsPfx)
            
            # Digest Method 
            digestMethodElem = refElem.createAppendElement(DSIG.BASE, 
                                                           'DigestMethod')
            digestMethodElem.setAttributeNS(None, 'Algorithm',DSIG.DIGEST_SHA1)
            
            # Digest Value
            digestValueElem = refElem.createAppendElement(DSIG.BASE, 
                                                          'DigestValue')
            digestValueElem.createAppendTextNode(digestValue)

   
        # 2) Signature Generation
        #        
        # Canonicalize the signedInfo node
        signedInfoInclusiveNsKWs = self.createUnsupressedPrefixKW(
                                                        self.signedInfoC14nKw)
        try:
            signedInfoElem = soapWriter.body.evaluate('//ds:SignedInfo',
                                                  processorNss=processorNss)[0]
        except TypeError, e:
            log.error("Error locating SignedInfo element for signature")
            raise 
        
        c14nSignedInfo=signedInfoElem.canonicalize(algorithm=signedInfoC14nAlg,
                                                   **signedInfoInclusiveNsKWs)
        # Calculate digest of SignedInfo
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Sign using the private key and base 64 encode the result
        signatureValue = self.signingPriKey.sign(signedInfoDigestValue)
        b64EncSignatureValue = base64.encodestring(signatureValue).strip()

        # Add to <SignatureValue>
        signatureValueElem.createAppendTextNode(b64EncSignatureValue)

        log.info("Signature generation complete")


    def createUnsupressedPrefixKW(self, dictToConvert):
        """
        Convert a dictionary to use keys with names, 'inclusive_namespaces' in
        place of keys with names 'unsupressedPrefixes'
        NB, this is required for the ZSI canonicalize method
        @type dictToConvert: dict
        @param dictToConvert: dictionary to convert
        @rtype: dict
        @return: dictionary with corrected keys
        """
        nsList = []
        newDict = dictToConvert.copy()
        if isinstance(newDict, dict) and \
            isinstance(newDict.get('inclusive_namespaces'), list):
            nsList = newDict.get('inclusive_namespaces')
            newDict.pop('inclusive_namespaces')

        newDict['unsuppressedPrefixes'] = nsList
        return newDict

    def verify(self, parsedSOAP, raiseNoSignatureFound=True):
        """Verify signature
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender"""

        processorNss = {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':SOAP.ENV 
        }
        signatureElem = parsedSOAP.dom.xpath('//ds:Signature', 
                                             explicitNss=processorNss)
        if len(signatureElem) > 1:
            raise VerifyError('Multiple <ds:Signature/> elements found')
        
        try:
            signatureElem = signatureElem[0]
        except IndexError:
            # Message wasn't signed
            msg = "Input message wasn't signed!"
            if raiseNoSignatureFound:
                raise NoSignatureFound(msg)
            else: 
                log.warning(msg)
                return
        
        # Two stage process: reference validation followed by signature 
        # validation 
        
        # 1) Reference Validation
        
        # Check for canonicalization set via ds:CanonicalizationMethod -
        # Use this later as a back up in case no Canonicalization was set in 
        # the transforms elements
        try:
            c14nMethodElem=parsedSOAP.dom.xpath('//ds:CanonicalizationMethod',
                                                explicitNss=processorNss)[0]
        except TypeError, e:
            log.error("XPath query error locating "
                      "<ds:CanonicalizationMethod/>: %s" % e)
            raise
        
        refElems = parsedSOAP.dom.xpath('//ds:Reference',
                                        explicitNss=processorNss)

        for refElem in refElems:
            # Get the URI for the reference
            refURI = refElem.getAttributeNS(None, 'URI')
            
            try:
                transformsElem = getElements(refElem, "Transforms")[0]
                transformElems = getElements(transformsElem, "Transform")
    
                refAlgorithm = transformElems[0].getAttributeNS(None,
                                                                'Algorithm')
            except Exception, e:
                raise VerifyError('failed to get transform algorithm for '
                                  '<ds:Reference URI="%s">' % 
                                  (refURI, e))
                
            # Add extra keyword for Exclusive canonicalization method
            refC14nKw = {}
            refC14nIsExcl = refAlgorithm == DSIG.C14N_EXCL
            if refC14nIsExcl:
                try:
                    # Check for no inclusive namespaces set
                    inclusiveNS = getElements(transformElems[0], 
                                              "InclusiveNamespaces")                   
                    if len(inclusiveNS) > 0:
                        pfxListAttElem=inclusiveNS[0].getAttributeNodeNS(None, 
                                                                'PrefixList')
                            
                        refC14nKw['inclusivePrefixes'] = \
                                                pfxListAttElem.value.split()
                    else:
                        refC14nKw['inclusivePrefixes'] = None
                except Exception, e:
                    raise VerifyError('failed to handle transform (%s) in '
                                      '<ds:Reference URI="%s">: %s' % \
                                      (transformElems[0], refURI, e))
        
            # Canonicalize the reference data and calculate the digest
            if refURI[0] != "#":
                raise VerifyError("Expecting # identifier for Reference URI "
                                  "\"%s\"" % refURI)
                    
            # XPath reference
            uriXPath = '//*[@wsu:Id="%s"]' % refURI[1:]
            uriElem = parsedSOAP.dom.xpath(uriXPath,
                                           explicitNss=processorNss)[0]

            f = StringIO()
            CanonicalPrint(uriElem, stream=f, exclusive=refC14nIsExcl,
                           **refC14nKw)
            refC14n = f.getvalue()
            digestValue = base64.encodestring(sha(refC14n).digest()).strip()
            
            # Extract the digest value that was stored            
            digestNode = getElements(refElem, "DigestValue")[0]
            nodeDigestValue = str(digestNode.childNodes[0].nodeValue).strip()   
            
            # Reference validates if the two digest values are the same
            if digestValue != nodeDigestValue:
                raise InvalidSignature('Digest Values do not match for URI: '
                                       '"%s"' % refURI)
            
            log.debug("Verified canonicalization for element %s" % refURI[1:])
                
        # 2) Signature Validation
        signedInfoElem = parsedSOAP.dom.xpath('//ds:SignedInfo',
                                              explicitNss=processorNss)[0]

        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        signedInfoC14nAlg = c14nMethodElem.getAttributeNS(None, "Algorithm")
        signedInfoC14nKw = {}
        signedInfoC14nIsExcl = signedInfoC14nAlg == DSIG.C14N_EXCL
        if signedInfoC14nIsExcl:
            try:
                # Check for inclusive namespaces
                inclusiveNsElem = getElements(c14nMethodElem,
                                              "InclusiveNamespaces")
                if len(inclusiveNsElem) > 0:                    
                    pfxListAttElem=inclusiveNsElem[0].getAttributeNodeNS(None,
                                                                 'PrefixList')
                    signedInfoC14nKw['inclusivePrefixes'] = \
                                                pfxListAttElem.value.split()
                else:
                    signedInfoC14nKw['inclusivePrefixes'] = None
            except Exception, e:
                raise VerifyError('failed to handle exclusive '
                                  'canonicalisation for SignedInfo: %s' % e)

        # Canonicalize the SignedInfo node and take digest
        f = StringIO()
        CanonicalPrint(signedInfoElem,
                       stream=f,
                       exclusive=signedInfoC14nIsExcl, 
                       **signedInfoC14nKw)       
        c14nSignedInfo = f.getvalue()  
                       
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Get the signature value in order to check against the digest just
        # calculated
        signatureValueElem = parsedSOAP.dom.xpath('//ds:SignatureValue',
                                                  explicitNss=processorNss)[0]

        # Remove base 64 encoding
        b64EncSignatureValue = signatureValueElem.childNodes[0].nodeValue
        signatureValue = base64.decodestring(b64EncSignatureValue)

        # Cache Signature Value here so that a response can include it.
        #
        # Nb. If the sign method is called from a separate SignatureHandler
        # object then the signature value must be passed from THIS object to
        # the other SignatureHandler otherwise signature confirmation will
        # fail
        if self.applySignatureConfirmation:
            # re-encode string to avoid possible problems with interpretation 
            # of line breaks
            self.b64EncSignatureValue = b64EncSignatureValue
        else:
            self.b64EncSignatureValue = None
         
        # Look for X.509 Cert in wsse:BinarySecurityToken node
        try:
            binSecTokElem = parsedSOAP.dom.xpath('//wsse:BinarySecurityToken',
                                                 explicitNss=processorNss)[0]
        except:
            # Signature may not have included the Binary Security Token in 
            # which case the verifying cert will need to have been set 
            # elsewhere
            log.info("No Binary Security Token found in WS-Security header")
            binSecTokElem = None
        
        if binSecTokElem:
            try:
                x509CertTxt=str(binSecTokElem.childNodes[0].nodeValue)
                
                valueType = binSecTokElem.getAttributeNS(None, "ValueType")
                if valueType in (self.__class__.binSecTokValType['X509v3'],
                                 self.__class__.binSecTokValType['X509']):
                    # Remove base 64 encoding
                    derString = base64.decodestring(x509CertTxt)
                    self.verifyingCert = X509Cert.Parse(derString, 
                                                    format=X509Cert.formatDER)
                    x509Stack = X509Stack()

                elif valueType == \
                    self.__class__.binSecTokValType['X509PKIPathv1']:
                    
                    derString = base64.decodestring(x509CertTxt)
                    x509Stack = X509StackParseFromDER(derString)
                    
                    # TODO: Check ordering - is the last off the stack the
                    # one to use to verify the message?
                    self.verifyingCert = x509Stack[-1]
                else:
                    raise WSSecurityError("BinarySecurityToken ValueType "
                                          'attribute is not recognised: "%s"' %
                                          valueType)
                               
            except Exception, e:
                raise VerifyError("Error extracting BinarySecurityToken "
                                  "from WSSE header: %s" % e)

        if self.verifyingCert is None:
            raise VerifyError("No certificate set for verification of the "
                              "signature")
        
        # Extract RSA public key from the cert
        rsaPubKey = self.verifyingCert.pubKey.get_rsa()

        # Apply the signature verification
        try:
            verify = rsaPubKey.verify(signedInfoDigestValue, signatureValue)
        except RSA.RSAError, e:
            raise VerifyError("Error in Signature: " % e)
        
        if not verify:
            raise InvalidSignature("Invalid signature")
        
        # Verify chain of trust 
        x509Stack.verifyCertChain(x509Cert2Verify=self.verifyingCert,
                                  caX509Stack=self._caX509Stack)
        
        self._verifyTimeStamp(parsedSOAP, 
                              processorNss,
                              timestampClockSkew=self.timestampClockSkew,
                              timestampMustBeSet=self.timestampMustBeSet,
                              createdElemMustBeSet=self.createdElemMustBeSet,
                              expiresElemMustBeSet=self.expiresElemMustBeSet) 
        log.info("Signature OK")        
