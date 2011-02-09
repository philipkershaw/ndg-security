"""DOM based WS-Security Encryption Handler

NOT COMPLETE OR TESTED

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/06/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

import logging
log = logging.getLogger(__name__)
from ndg.security.common.wssecurity import WSSecurityError

class EncryptionError(WSSecurityError):
    """Flags an error in the encryption process"""

class DecryptionError(WSSecurityError):
    """Raised from EncryptionHandler.decrypt if an error occurs with the
    decryption process"""


class EncryptionHandler(object):
    """Encrypt/Decrypt SOAP messages using WS-Security""" 
    
    # Map namespace URIs to Crypto algorithm module and mode 
    cryptoAlg = \
    {
         _ENCRYPTION.WRAP_AES256:      {'module':       AES, 
                                        'mode':         AES.MODE_ECB,
                                        'blockSize':    16},
         
         # CBC (Cipher Block Chaining) modes
         _ENCRYPTION.BLOCK_AES256:     {'module':       AES, 
                                        'mode':         AES.MODE_CBC,
                                        'blockSize':    16},
                                        
         _ENCRYPTION.BLOCK_TRIPLEDES:  {'module':       DES3, 
                                        'mode':         DES3.MODE_CBC,
                                        'blockSize':    8}   
    }

     
    def __init__(self,
                 signingCertFilePath=None, 
                 signingPriKeyFilePath=None, 
                 signingPriKeyPwd=None,
                 chkSecurityTokRef=False,
                 encrNS=_ENCRYPTION.BLOCK_AES256):
        
        self.__signingCertFilePath = signingCertFilePath
        self.__signingPriKeyFilePath = signingPriKeyFilePath
        self.__signingPriKeyPwd = signingPriKeyPwd
        
        self.__chkSecurityTokRef = chkSecurityTokRef
        
        # Algorithm for shared key encryption
        try:
            self.__encrAlg = self.cryptoAlg[encrNS]
            
        except KeyError:
            raise EncryptionError, \
        'Input encryption algorithm namespace "%s" is not supported' % encrNS

        self.__encrNS = encrNS
        
        
    def encrypt(self, soapWriter):
        """Encrypt an outbound SOAP message
        
        Use Key Wrapping - message is encrypted using a shared key which 
        itself is encrypted with the public key provided by the X.509 cert.
        signingCertFilePath"""
        
        # Use X.509 Cert to encrypt
        x509Cert = X509.load_cert(self.__signingCertFilePath)
        
        soapWriter.dom.setNamespaceAttribute('wsse', OASIS.WSSE)
        soapWriter.dom.setNamespaceAttribute('xenc', _ENCRYPTION.BASE)
        soapWriter.dom.setNamespaceAttribute('ds', DSIG.BASE)
        
        # TODO: Put in a check to make sure <wsse:security> isn't already 
        # present in header
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                         'Security')
        wsseElem.node.setAttribute('SOAP-ENV:mustUnderstand', "1")
        
        encrKeyElem = wsseElem.createAppendElement(_ENCRYPTION.BASE, 
                                                   'EncryptedKey')
        
        # Encryption method used to encrypt the shared key
        keyEncrMethodElem = encrKeyElem.createAppendElement(_ENCRYPTION.BASE, 
                                                        'EncryptionMethod')
        
        keyEncrMethodElem.node.setAttribute('Algorithm', 
                                            _ENCRYPTION.KT_RSA_1_5)


        # Key Info
        KeyInfoElem = encrKeyElem.createAppendElement(DSIG.BASE, 'KeyInfo')
        
        secTokRefElem = KeyInfoElem.createAppendElement(OASIS.WSSE, 
                                                  'SecurityTokenReference')
        
        x509IssSerialElem = secTokRefElem.createAppendElement(DSIG.BASE, 
                                                          'X509IssuerSerial')

        
        x509IssNameElem = x509IssSerialElem.createAppendElement(DSIG.BASE, 
                                                          'X509IssuerName')
        x509IssNameElem.createAppendTextNode(x509Cert.get_issuer().as_text())

        
        x509IssSerialNumElem = x509IssSerialElem.createAppendElement(
                                                  DSIG.BASE, 
                                                  'X509IssuerSerialNumber')
        
        x509IssSerialNumElem.createAppendTextNode(
                                          str(x509Cert.get_serial_number()))

        # References to what has been encrypted
        encrKeyCiphDataElem = encrKeyElem.createAppendElement(
                                                          _ENCRYPTION.BASE,
                                                          'CipherData')
        
        encrKeyCiphValElem = encrKeyCiphDataElem.createAppendElement(
                                                          _ENCRYPTION.BASE,
                                                          'CipherValue')

        # References to what has been encrypted
        refListElem = encrKeyElem.createAppendElement(_ENCRYPTION.BASE,
                                                      'ReferenceList')
        
        dataRefElem = refListElem.createAppendElement(_ENCRYPTION.BASE,
                                                      'DataReference')
        dataRefElem.node.setAttribute('URI', "#encrypted")

                     
        # Add Encrypted data to SOAP body
        encrDataElem = soapWriter.body.createAppendElement(_ENCRYPTION.BASE, 
                                                           'EncryptedData')
        encrDataElem.node.setAttribute('Id', 'encrypted')
        encrDataElem.node.setAttribute('Type', _ENCRYPTION.BASE)  
              
        # Encryption method used to encrypt the target data
        dataEncrMethodElem = encrDataElem.createAppendElement(
                                                      _ENCRYPTION.BASE, 
                                                      'EncryptionMethod')
        
        dataEncrMethodElem.node.setAttribute('Algorithm', self.__encrNS)
        
        # Cipher data
        ciphDataElem = encrDataElem.createAppendElement(_ENCRYPTION.BASE,
                                                        'CipherData')
        
        ciphValueElem = ciphDataElem.createAppendElement(_ENCRYPTION.BASE,
                                                         'CipherValue')


        # Get elements from SOAP body for encryption
        dataElem = soapWriter.body.node.childNodes[0]
        data = dataElem.toxml()
     
        # Pad data to nearest multiple of encryption algorithm's block size    
        modData = len(data) % self.__encrAlg['blockSize']
        nPad = modData and self.__encrAlg['blockSize'] - modData or 0
        
        # PAd with random junk but ...
        data += os.urandom(nPad-1)
        
        # Last byte should be number of padding bytes
        # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
        data += chr(nPad)       
        
        # Generate shared key and input vector - for testing use hard-coded 
        # values to allow later comparison              
        sharedKey = os.urandom(self.__encrAlg['blockSize'])
        iv = os.urandom(self.__encrAlg['blockSize'])
        
        alg = self.__encrAlg['module'].new(sharedKey,
                                           self.__encrAlg['mode'],
                                           iv)
 
        # Encrypt required elements - prepend input vector
        encryptedData = alg.encrypt(iv + data)
        dataCiphValue = base64.encodestring(encryptedData).strip()

        ciphValueElem.createAppendTextNode(dataCiphValue)
        
        
        # ! Delete unencrypted message body elements !
        soapWriter.body.node.removeChild(dataElem)

        
        # Use X.509 cert public key to encrypt the shared key - Extract key
        # from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()
        
        # Encrypt the shared key
        encryptedSharedKey = rsaPubKey.public_encrypt(sharedKey, 
                                                      RSA.pkcs1_padding)
        
        encrKeyCiphVal = base64.encodestring(encryptedSharedKey).strip()
        
        # Add the encrypted shared key to the EncryptedKey section in the SOAP
        # header
        encrKeyCiphValElem.createAppendTextNode(encrKeyCiphVal)

#        print soapWriter.dom.node.toprettyxml()
#        import pdb;pdb.set_trace()
        
        
    def decrypt(self, parsedSOAP):
        """Decrypt an inbound SOAP message"""
        
        processorNss = \
        {
            'xenc':   _ENCRYPTION.BASE,
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(parsedSOAP.dom, processorNss=processorNss)
        
        refListNodes = xpath.Evaluate('//xenc:ReferenceList', 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)
        if len(refListNodes) > 1:
            raise DecryptionError, 'Expecting a single ReferenceList element'
        
        try:
            refListNode = refListNodes[0]
        except:
            # Message wasn't encrypted - is this OK or is a check needed for
            # encryption info in SOAP body - enveloped form?
            return


        # Check for wrapped key encryption
        encrKeyNodes = xpath.Evaluate('//xenc:EncryptedKey', 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)
        if len(encrKeyNodes) > 1:
            raise DecryptionError, 'This implementation can only handle ' + \
                                   'single EncryptedKey element'
        
        try:
            encrKeyNode = encrKeyNodes[0]
        except:
            # Shared key encryption used - leave out for the moment
            raise DecryptionError, 'This implementation can only handle ' + \
                                   'wrapped key encryption'

        
        # Check encryption method
        keyEncrMethodNode = getElements(encrKeyNode, 'EncryptionMethod')[0]     
        keyAlgorithm = keyEncrMethodNode.getAttributeNode("Algorithm").value
        if keyAlgorithm != _ENCRYPTION.KT_RSA_1_5:
            raise DecryptionError, \
            'Encryption algorithm for wrapped key is "%s", expecting "%s"' % \
                (keyAlgorithm, _ENCRYPTION.KT_RSA_1_5)

                                                            
        if self.__chkSecurityTokRef and self.__signingCertFilePath:
             
            # Check input cert. against SecurityTokenReference
            securityTokRefXPath = '/ds:KeyInfo/wsse:SecurityTokenReference'
            securityTokRefNode = xpath.Evaluate(securityTokRefXPath, 
                                                contextNode=encrKeyNode, 
                                                context=ctxt)
            # TODO: Look for ds:X509* elements to check against X.509 cert 
            # input


        # Look for cipher data for wrapped key
        keyCiphDataNode = getElements(encrKeyNode, 'CipherData')[0]
        keyCiphValNode = getElements(keyCiphDataNode, 'CipherValue')[0]

        keyCiphVal = str(keyCiphValNode.childNodes[0].nodeValue)
        encryptedKey = base64.decodestring(keyCiphVal)

        # Read RSA Private key in order to decrypt wrapped key  
        priKeyFile = BIO.File(open(self.__signingPriKeyFilePath))          
        pwdCallback = lambda *ar, **kw: self.__signingPriKeyPwd                                        
        priKey = RSA.load_key_bio(priKeyFile, callback=pwdCallback)
        
        sharedKey = priKey.private_decrypt(encryptedKey, RSA.pkcs1_padding)
        

        # Check list of data elements that have been encrypted
        for dataRefNode in refListNode.childNodes:

            # Get the URI for the reference
            dataRefURI = dataRefNode.getAttributeNode('URI').value                            
            if dataRefURI[0] != "#":
                raise VerifyError, \
                    "Expecting # identifier for DataReference URI \"%s\"" % \
                    dataRefURI

            # XPath reference - need to check for wsu namespace qualified?
            #encrNodeXPath = '//*[@wsu:Id="%s"]' % dataRefURI[1:]
            encrNodeXPath = '//*[@Id="%s"]' % dataRefURI[1:]
            encrNode = xpath.Evaluate(encrNodeXPath, 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)[0]
                
            dataEncrMethodNode = getElements(encrNode, 'EncryptionMethod')[0]     
            dataAlgorithm = \
                        dataEncrMethodNode.getAttributeNode("Algorithm").value
            try:        
                # Match algorithm name to Crypto module
                CryptoAlg = self.cryptoAlg[dataAlgorithm]
                
            except KeyError:
                raise DecryptionError, \
'Encryption algorithm for data is "%s", supported algorithms are:\n "%s"' % \
                    (keyAlgorithm, "\n".join(self.cryptoAlg.keys()))

            # Get Data
            dataCiphDataNode = getElements(encrNode, 'CipherData')[0]
            dataCiphValNode = getElements(dataCiphDataNode, 'CipherValue')[0]
        
            dataCiphVal = str(dataCiphValNode.childNodes[0].nodeValue)
            encryptedData = base64.decodestring(dataCiphVal)
            
            alg = CryptoAlg['module'].new(sharedKey, CryptoAlg['mode'])
            decryptedData = alg.decrypt(encryptedData)
            
            # Strip prefix - assume is block size
            decryptedData = decryptedData[CryptoAlg['blockSize']:]
            
            # Strip any padding suffix - Last byte should be number of padding
            # bytes
            # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
            lastChar = decryptedData[-1]
            nPad = ord(lastChar)
            
            # Sanity check - there may be no padding at all - the last byte 
            # being the end of the encrypted XML?
            #
            # TODO: are there better sanity checks than this?!
            if nPad < CryptoAlg['blockSize'] and nPad > 0 and \
               lastChar != '\n' and lastChar != '>':
                
                # Follow http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block -
                # last byte gives number of padding bytes
                decryptedData = decryptedData[:-nPad]


            # Parse the encrypted data - inherit from Reader as a fudge to 
            # enable relevant namespaces to be added prior to parse
            processorNss.update({'xsi': SCHEMA.XSI3, 'ns1': 'urn:ZSI:examples'})
            class _Reader(Reader):
                def initState(self, ownerDoc=None):
                    Reader.initState(self, ownerDoc=ownerDoc)
                    self._namespaces.update(processorNss)
                    
            rdr = _Reader()
            dataNode = rdr.fromString(decryptedData, ownerDoc=parsedSOAP.dom)
            
            # Add decrypted element to parent and remove encrypted one
            parentNode = encrNode._get_parentNode()
            parentNode.appendChild(dataNode)
            parentNode.removeChild(encrNode)
            
            from xml.dom.ext import ReleaseNode
            ReleaseNode(encrNode)
            
            # Ensure body_root attribute is up to date in case it was
            # previously encrypted
            parsedSOAP.body_root = parsedSOAP.body.childNodes[0]
            #print decryptedData
            #import pdb;pdb.set_trace()
