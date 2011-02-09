""" DOM based WS-Security digital signature handler

NERC DataGrid Project
"""
__author__ = "C Byrom"
__date__ = "18/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'


import re

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
import base64

import os

import ZSI
from ZSI.wstools.Namespaces import DSIG, WSA200403, \
                                   SOAP, SCHEMA # last included for xsi

from ZSI.TC import ElementDeclaration,TypeDefinition
from ZSI.generate.pyclass import pyclass_type

from ZSI.wstools.Utility import DOMException
from ZSI.wstools.Utility import NamespaceError, MessageInterface, ElementProxy

# Canonicalization
from ZSI.wstools.c14n import Canonicalize

from xml.xpath.Context import Context
from xml import xpath

# Include for re-parsing doc ready for canonicalization in sign method - see
# associated note
from xml.dom.ext.reader.PyExpat import Reader

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
from ndg.security.common.wssecurity import WSSecurityError
from ndg.security.common.wssecurity.signaturehandler import _WSU, OASIS, \
    BaseSignatureHandler, NoSignatureFound, InvalidSignature, TimestampError, \
    MessageExpired, VerifyError, SignatureError

from ndg.security.common.X509 import X509Cert, X509CertParse, X509CertRead, \
    X509Stack, X509StackParseFromDER


# Helper functions     
def getElements(node, nameList):
    '''DOM Helper function for getting child elements from a given node'''
    # Avoid sub-string matches
    nameList = isinstance(nameList, basestring) and [nameList] or nameList
    return [n for n in node.childNodes if str(n.localName) in nameList]


def getChildNodes(node, nodeList=None):
    if nodeList is None:
        nodeList = [node] 
    return _getChildNodes(node, nodeList)
           
def _getChildNodes(node, nodeList):

    if node.attributes is not None:
        nodeList += node.attributes.values() 
    nodeList += node.childNodes
    for childNode in node.childNodes:
        _getChildNodes(childNode, nodeList)
    return nodeList


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
        sigConfirmElem.node.setAttribute('wsu:Id', "signatureConfirmation")

        # Add ID so that the element can be included in the signature
        # Following line is a hck to avoid appearance of #x when serialising \n
        # chars TODO: why is this happening??
        b64EncSignatureValue = ''.join(self.b64EncSignatureValue.split('\n'))
        sigConfirmElem.node.setAttribute('Value', b64EncSignatureValue)
        
        
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
        timestampElem.node.setAttribute('wsu:Id', "timestamp")
        
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
                         ctxt,
                         timestampClockSkew=0., 
                         timestampMustBeSet=False,
                         createdElemMustBeSet=True,
                         expiresElemMustBeSet=True):
        """Call from verify to check timestamp if found.  
        
        TODO: refactor as separate timestamp handler independent of 
        signature handler?
        
        @type parsedSOAP: ZSI.parse.ParsedSoap
        @param parsedSOAP: object contain parsed SOAP message received from
        sender
        @type ctxt:
        @param ctxt: XPath context object
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
            timestampNode = xpath.Evaluate('//wsu:Timestamp',
                                           contextNode=parsedSOAP.dom,
                                           context=ctxt)[0]
        except IndexError:
            msg = "Verifying message - No timestamp element found"
            if timestampMustBeSet:
                raise TimestampError(msg)
            else:
                log.warning(msg)
                return
        
        # Time now 
        dtNow = datetime.utcnow() + timedelta(seconds=timestampClockSkew)

        createdNode = timestampNode.getElementsByTagName("wsu:Created")
        if createdNode is None:
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
                            createdNode[0].childNodes[0].nodeValue.split('.')
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
        
        expiresNode = timestampNode.getElementsByTagName("wsu:Expires")
        if expiresNode is None:
            msg = ("Verifying message: no <wsu:Expires/> element found in "
                   "Timestamp")
            if expiresElemMustBeSet:
                raise TimestampError(msg)
            else:
                log.warning(msg)
        else:
            try:
                expiresDateTime, expiresSecFraction = \
                            expiresNode[0].childNodes[0].nodeValue.split('.')
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
        
        refC14nPfxSet = False
        if self.refC14nIsExcl:
            refC14nPfxSet = True 

        signedInfoC14nPfxSet = False
        if self.signedInfoC14nIsExcl:
            signedInfoC14nPfxSet = True
                
        if refC14nPfxSet or signedInfoC14nPfxSet:
           soapWriter._header.setNamespaceAttribute('ec', DSIG.C14N_EXCL)
        
        # Check <wsse:security> isn't already present in header
        ctxt = Context(soapWriter.dom.node, processorNss=processorNss)
        wsseNodes = xpath.Evaluate('//wsse:security', 
                                   contextNode=soapWriter.dom.node, 
                                   context=ctxt)
        if len(wsseNodes) > 1:
            raise SignatureError('wsse:Security element is already present')

        # Add WSSE element
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                          'Security')
        wsseElem.setNamespaceAttribute('wsse', OASIS.WSSE)
        
        # Recipient MUST parse and check this signature 
        wsseElem.node.setAttribute('SOAP-ENV:mustUnderstand', "1")
        
        # Binary Security Token element will contain the X.509 cert 
        # corresponding to the private key used to sing the message
        binSecTokElem = wsseElem.createAppendElement(OASIS.WSSE, 
                                                     'BinarySecurityToken')
        
        # Value type can be any be any one of those supported via 
        # binSecTokValType
        binSecTokElem.node.setAttribute('ValueType', 
                                        self.reqBinSecTokValType)

        binSecTokElem.node.setAttribute('EncodingType', self._binSecTokEncType)
        
        # Add ID so that the binary token can be included in the signature
        binSecTokElem.node.setAttribute('wsu:Id', "binaryToken")

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
        
        c14nMethodElem.node.setAttribute('Algorithm', signedInfoC14nAlg)
        
        if signedInfoC14nPfxSet:
            c14nInclNamespacesElem = c14nMethodElem.createAppendElement(
                                                    signedInfoC14nAlg,
                                                    'InclusiveNamespaces')
            c14nInclNamespacesElem.node.setAttribute('PrefixList', 
			    ' '.join(self.signedInfoC14nKw['inclusive_namespaces']))
        
        # Signed Info - Signature method
        sigMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                           'SignatureMethod')
        sigMethodElem.node.setAttribute('Algorithm', DSIG.SIG_RSA_SHA1)
        
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
        wsseRefElem.node.setAttribute('URI', "#binaryToken")
        
        # Add Reference to body so that it can be included in the signature
        soapWriter.body.node.setAttribute('wsu:Id', "body")
        soapWriter.body.node.setAttribute('xmlns:wsu', _WSU.UTILITY)

        # Serialize and re-parse prior to reference generation - calculating
        # canonicalization based on soapWriter.dom.node seems to give an
        # error: the order of wsu:Id attribute is not correct
        try:
            docNode = Reader().fromString(str(soapWriter))
        except Exception, e:
            raise SignatureError("Error parsing SOAP message for signing: %s"%
                                 e)

        ctxt = Context(docNode, processorNss=processorNss)
        refNodes = xpath.Evaluate('//*[@wsu:Id]', 
                                  contextNode=docNode, 
                                  context=ctxt)

        # Set based on 'signedInfoIsExcl' property
        refC14nAlg = c14nAlgOpt[int(self.refC14nIsExcl)]
        
        # 1) Reference Generation
        #
        # Find references
        for refNode in refNodes:
            
            refID = refNode.attributes[(_WSU.UTILITY, 'Id')].value
            
            # Set URI attribute to point to reference to be signed
            uri = u"#" + refID
            
            # Canonicalize reference
            inclusiveNSKWs = self.createUnsupressedPrefixKW(self.refC14nKw)
            refSubsetList = getChildNodes(refNode)
            refC14n = Canonicalize(docNode, 
                                   None, 
                                   subset=refSubsetList,
                                   **inclusiveNSKWs)
            
            # Calculate digest for reference and base 64 encode
            #
            # Nb. encodestring adds a trailing newline char
            digestValue = base64.encodestring(sha(refC14n).digest()).strip()


            # Add a new reference element to SignedInfo
            refElem = signedInfoElem.createAppendElement(DSIG.BASE, 
                                                         'Reference')
            refElem.node.setAttribute('URI', uri)
            
            # Use ds:Transforms or wsse:TransformationParameters?
            transformsElem = refElem.createAppendElement(DSIG.BASE, 
                                                         'Transforms')
            transformElem = transformsElem.createAppendElement(DSIG.BASE, 
                                                               'Transform')

            # Set Canonicalization algorithm type
            transformElem.node.setAttribute('Algorithm', refC14nAlg)
            if refC14nPfxSet:
                # Exclusive C14N requires inclusive namespace elements
                inclNamespacesElem = transformElem.createAppendElement(
							                           refC14nAlg,
                                                       'InclusiveNamespaces')
                inclNamespacesElem.node.setAttribute('PrefixList',
				        ' '.join(self.refC14nKw['inclusive_namespaces']))
            
            # Digest Method 
            digestMethodElem = refElem.createAppendElement(DSIG.BASE, 
                                                           'DigestMethod')
            digestMethodElem.node.setAttribute('Algorithm', DSIG.DIGEST_SHA1)
            
            # Digest Value
            digestValueElem = refElem.createAppendElement(DSIG.BASE, 
                                                          'DigestValue')
            digestValueElem.createAppendTextNode(digestValue)

   
        # 2) Signature Generation
        #        
        # Canonicalize the signedInfo node
        docNode = Reader().fromString(str(soapWriter))
        ctxt = Context(docNode, processorNss=processorNss)
        signedInfoNode = xpath.Evaluate('//ds:SignedInfo', 
                                        contextNode=docNode, 
                                        context=ctxt)[0]

        signedInfoSubsetList = getChildNodes(signedInfoNode)
        
        inclusiveNSKWs = self.createUnsupressedPrefixKW(self.signedInfoC14nKw)
        c14nSignedInfo = Canonicalize(docNode, 
                                      None, 
                                      subset=signedInfoSubsetList,
                                      **inclusiveNSKWs)

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

        processorNss = \
        {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(parsedSOAP.dom, processorNss=processorNss)
        

        signatureNodes = xpath.Evaluate('//ds:Signature', 
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)
        if len(signatureNodes) > 1:
            raise VerifyError, 'Multiple ds:Signature elements found'
        
        try:
            signatureNodes = signatureNodes[0]
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
        c14nMethodNode = xpath.Evaluate('//ds:CanonicalizationMethod', 
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)[0]
        
        refNodes = xpath.Evaluate('//ds:Reference', 
                                  contextNode=parsedSOAP.dom, 
                                  context=ctxt)

        for refNode in refNodes:
            # Get the URI for the reference
            refURI = refNode.getAttributeNode('URI').value
			# skip checking of binary token - since this cannot be
			# included in the message if using a Java client with Rampart1.3
            if refURI == "binaryToken":
                continue
                         
            try:
                transformsNode = getElements(refNode, "Transforms")[0]
                transforms = getElements(transformsNode, "Transform")
    
                refAlgorithm=transforms[0].getAttributeNode("Algorithm").value
            except Exception, e:
                raise VerifyError('failed to get transform algorithm for '
                                  '<ds:Reference URI="%s">' % \
                                  (refURI, str(e)))
                
            # Add extra keyword for Exclusive canonicalization method
            refC14nKw = {}
            if refAlgorithm == DSIG.C14N_EXCL:
                try:
                    # Check for no inclusive namespaces set
                    inclusiveNS = getElements(transforms[0], 
                                              "InclusiveNamespaces")                    
                    if inclusiveNS:
                        pfxListAttNode = \
                                inclusiveNS[0].getAttributeNode('PrefixList')
                            
                        refC14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
                    else:
                        # Set to empty list to ensure Exclusive C14N is set for
                        # Canonicalize call
                        refC14nKw['unsuppressedPrefixes'] = []
                except Exception, e:
                    raise VerifyError('failed to handle transform (%s) in '
                                      '<ds:Reference URI="%s">: %s' % \
                                      (transforms[0], refURI, e))
        
            # Canonicalize the reference data and calculate the digest
            if refURI[0] != "#":
                raise VerifyError("Expecting # identifier for Reference URI "
                                  "\"%s\"" % refURI)
                    
            # XPath reference
            uriXPath = '//*[@wsu:Id="%s"]' % refURI[1:]
            uriNode = xpath.Evaluate(uriXPath, 
                                     contextNode=parsedSOAP.dom, 
                                     context=ctxt)[0]

            refSubsetList = getChildNodes(uriNode)
            refC14n = Canonicalize(parsedSOAP.dom,
                                   None, 
                                   subset=refSubsetList,
                                   **refC14nKw)
            digestValue = base64.encodestring(sha(refC14n).digest()).strip()
            
            # Extract the digest value that was stored            
            digestNode = getElements(refNode, "DigestValue")[0]
            nodeDigestValue = str(digestNode.childNodes[0].nodeValue).strip()   
            
            # Reference validates if the two digest values are the same
            if digestValue != nodeDigestValue:
                raise InvalidSignature('Digest Values do not match for URI: '
                                       '"%s"' % refURI)
            
            log.info("Verified canonicalization for element %s" % refURI[1:])
                
        # 2) Signature Validation
        signedInfoNode = xpath.Evaluate('//ds:SignedInfo',
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)[0]

        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        signedInfoC14nAlg = c14nMethodNode.getAttributeNode("Algorithm").value
        signedInfoC14nKw = {}
        if signedInfoC14nAlg == DSIG.C14N_EXCL:
            try:
                # Check for inclusive namespaces
                inclusiveNS = c14nMethodNode.getElementsByTagName(
                                                        "InclusiveNamespaces")
                if inclusiveNS:                    
                    pfxListAttNode = inclusiveNS[0].getAttributeNode(\
                                                                 'PrefixList')
                    signedInfoC14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
                else:
                    # Must default to [] otherwise exclusive C14N is not
                    # triggered
                    signedInfoC14nKw['unsuppressedPrefixes'] = []
            except Exception, e:
                raise VerifyError('failed to handle exclusive '
                                  'canonicalisation for SignedInfo: %s' % e)

        # Canonicalize the SignedInfo node and take digest
        signedInfoSubsetList = getChildNodes(signedInfoNode)
        c14nSignedInfo = Canonicalize(parsedSOAP.dom, 
                                      None, 
                                      subset=signedInfoSubsetList,
                                      **signedInfoC14nKw)
                              
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Get the signature value in order to check against the digest just
        # calculated
        signatureValueNode = xpath.Evaluate('//ds:SignatureValue',
                                            contextNode=parsedSOAP.dom, 
                                            context=ctxt)[0]

        # Remove base 64 encoding
        # This line necessary? - only decode call needed??  pyGridWare vers
        # seems to preserve whitespace
#        b64EncSignatureValue = \
#                    str(signatureValueNode.childNodes[0].nodeValue).strip()
        b64EncSignatureValue = signatureValueNode.childNodes[0].nodeValue
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
            binSecTokNode = xpath.Evaluate('//wsse:BinarySecurityToken',
                                           contextNode=parsedSOAP.dom,
                                           context=ctxt)[0]
        except:
            # Signature may not have included the Binary Security Token in 
            # which case the verifying cert will need to have been set 
            # elsewhere
            log.info("No Binary Security Token found in WS-Security header")
            binSecTokNode = None
        
        if binSecTokNode:
            try:
                x509CertTxt=str(binSecTokNode.childNodes[0].nodeValue)
                
                valueType = binSecTokNode.getAttributeNode("ValueType").value
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
                              ctxt,
                              timestampClockSkew=self.timestampClockSkew,
                              timestampMustBeSet=self.timestampMustBeSet,
                              createdElemMustBeSet=self.createdElemMustBeSet,
                              expiresElemMustBeSet=self.expiresElemMustBeSet) 

        log.info("Signature OK")        
