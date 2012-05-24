"""MyProxy Web Service client package

"""
__author__ = "P J Kershaw"
__date__ = "09/12/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from OpenSSL import SSL, crypto
from ndg.httpsclient.urllib2_build_opener import build_opener


class MyProxyWSClient(object):
    PRIKEY_NBITS = 4096
    MESSAGE_DIGEST_TYPE = "md5"
    CERT_REQ_POST_PARAM_KEYNAME = 'certificate_request'
    
    def __init__(self):
        self.caDir = None
        self.timeout = 500

    @staticmethod
    def create_key_pair(n_bits_for_key=PRIKEY_NBITS):
        """Generate key pair and return as PEM encoded string
        @type n_bits_for_key: int
        @param n_bits_for_key: number of bits for private key generation - 
        default is 2048
        @rtype: OpenSSL.crypto.PKey
        @return: public/private key pair
        """
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, n_bits_for_key)
        
        return key_pair
            
    @staticmethod
    def create_cert_req(key_pair, message_digest=MESSAGE_DIGEST_TYPE):
        """Create a certificate request.
        
        @type CN: basestring
        @param CN: Common Name for certificate - effectively the same as the
        username for the MyProxy credential
        @type keyPair: string/None
        @param keyPair: public/private key pair
        @type messageDigest: basestring
        @param messageDigest: message digest type - default is MD5
        @rtype: base string
        @return certificate request PEM text and private key PEM text
        """
        
        # Check all required certifcate request DN parameters are set                
        # Create certificate request
        cert_req = crypto.X509Req()
        
        # Create public key object
        cert_req.set_pubkey(key_pair)
        
        # Add the public key to the request
        cert_req.sign(key_pair, message_digest)
        
        cert_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM, 
                                                   cert_req)

        return cert_req
        
    def logon(self, username, password, myproxy_server_url, cert_life_time):
        """Obtain a new certificate"""
        ctx = SSL.Context(SSL.SSLv3_METHOD)
        verify_callback = lambda conn, x509, errnum, errdepth, preverify_ok: \
            preverify_ok 
            
        ctx.set_verify(SSL.VERIFY_PEER, verify_callback)
        ctx.load_verify_locations(None, self.caDir)
        opener = build_opener(ssl_context=ctx)
        
        key_pair = self.__class__.create_key_pair()
        cert_req = self.__class__.create_cert_req(key_pair)
        
        req = "%s=%s\n" % (self.__class__.CERT_REQ_POST_PARAM_KEYNAME, cert_req)
        res = opener.open(myproxy_server_url, req, self.timeout)
        
        return res
        
    def get_trustroots(self):
        """Get trustroots"""
