"""
MyProxy Client interface - extending the SessionManager AbstractAuthNService 
interface - to allow use with SessionManager

NERC Data Grid Project
"""
__author__ = "C Byrom - Tessella"
__date__ = "28/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

from ndg.security.server.sessionmanager import AbstractAuthNService
from ndg.security.common.myproxy import MyProxyClient

class MyProxyAuthN(AbstractAuthNService):
    '''Provide an Authentication interface to the Session Manager utilising
    MyProxy'''
    
    def __init__(self, propFilePath=None, **prop):
        '''Instantiate MyProxy client object taking in settings from the 
        properties file'''
        self._myProxyClnt = MyProxyClient(propFilePath=propFilePath)
        
    def logon(self, username, passphrase):
        '''Implementation of AbstractAuthNService logon for a MyProxy client
        @type username: basestring
        @param username: username for account login
        @type passphrase: basestring
        @param passphrase: passphrase (or password) for user account
        '''
        self._myProxyClnt.logon(username, password)