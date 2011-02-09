"""
Basic Authentication interface - extending the SessionManager 
AbstractAuthNService interface - to allow use with SessionManager

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "08/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
try:
    from hashlib import md5
except ImportError:
    # Allow for < Python 2.5
    from md5 import md5

from ndg.security.server.sessionmanager import SessionManager, \
    AbstractAuthNService, AuthNServiceInvalidCredentials, AuthNServiceError

class BasicAuthN(AbstractAuthNService):
    '''Provide a basic Authentication interface to the Session Manager 
    based on username/password entries in a config file'''
    
    def __init__(self, **prop):
        '''Instantiate object taking in settings from the input
        properties'''
        accounts = prop.get('accounts', []).split()
        self.accounts=dict([tuple(account.split(':')) for account in accounts])
       
    def logon(self, username, passphrase):
        '''Implementation of AbstractAuthNService logon
        @type username: basestring
        @param username: username for account login
        @type passphrase: basestring
        @param passphrase: passphrase (or password) for user account
        @rtype: None
        @return: this interface doesn't return any user PKI credentials.
        '''
        try:
            md5Passwd = md5(passphrase).hexdigest()
        except Exception, e:
            raise AuthNServiceError("%s exception raised making a digest of "
                                    "the input passphrase: %s" % \
                                    (e.__class__, e))

        if self.accounts.get(username) != md5Passwd:
            raise AuthNServiceInvalidCredentials()