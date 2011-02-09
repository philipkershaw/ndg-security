"""
Session Manager Authentication interface returning a user cert/private key -
for use with Session Manager unittests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
log = logging.getLogger(__name__)

from M2Crypto import RSA

from ndg.security.server.sessionmanager import SessionManager, \
    AbstractAuthNService, AuthNServiceInvalidCredentials, AuthNServiceError
from ndg.security.common.myproxy import MyProxyClient

class UserX509CertAuthN(AbstractAuthNService):
    '''Test Authentication interface to the Session Manager 
    returning a certificate and private key
    
    For use with SessionManager unittests only'''
    
    def __init__(self, **prop):
        '''Instantiate client object from X.509 cert and private key file path
        inputs.  Private key must be none password protected.'''
        self.userX509Cert = open(prop['userX509CertFilePath']).read()
        self.userPriKey = open(prop['userPriKeyFilePath']).read()
        
    def logon(self, username, passphrase):
        '''Implementation of AbstractAuthNService logon for Session Manager
        unittests.  TEST ONLY - no check is carried out on username/passphrase
        credentials
        
        @type username: basestring
        @param username: username for account login
        @type passphrase: basestring
        @param passphrase: passphrase (or password) for user account
        @rtype: tuple
        @return: user PKI credentials.
        '''
        
        # Check password by executing a trial load of the private key
        try:
            RSA.load_key_string(self.userPriKey, 
                                callback=lambda *ar, **kw: passphrase)
        except RSA.RSAError, e:
            raise AuthNServiceInvalidCredentials(e)
        
        return self.userX509Cert, self.userPriKey