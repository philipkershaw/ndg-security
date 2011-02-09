"""
Database based Authentication interface implementation of the SessionManager
AbstractAuthNService interface 

Interface uses SQLAlchemy to enable support for multiple database vendors

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "25/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
log = logging.getLogger(__name__)
try:
    from hashlib import md5
except ImportError:
    # Allow for < Python 2.5
    from md5 import md5

from string import Template
from sqlalchemy import create_engine

from ndg.security.server.sessionmanager import SessionManager, \
    AbstractAuthNService, AuthNServiceInvalidCredentials, AuthNServiceError

class DatabaseAuthN(AbstractAuthNService):
    '''Provide a database based Authentication interface to the Session Manager 
    making use of the SQLAlchemy database package'''
    
    def __init__(self, **prop):
        '''Instantiate object taking in settings from the input
        properties'''
        try:
            self.connectionString = prop['connectionString']
            self.sqlQuery = prop['sqlQuery']
        except KeyError, e:
            raise AuthNServiceError("Missing property setting: %s" % e)
        
        self.isMD5EncodedPwd = prop.get('isMD5EncodedPwd', False)
       
    def logon(self, username, passphrase):
        '''Implementation of AbstractAuthNService for database authentication
        via SQLAlchemy
        
        @type username: basestring
        @param username: username for account login
        @type passphrase: basestring
        @param passphrase: passphrase (or password) for user account
        @rtype: None
        @return: this interface doesn't return any user PKI credentials.
        '''
        if self.isMD5EncodedPwd:
            try:
                passwd = md5(passphrase).hexdigest()
            except Exception, e:
                raise AuthNServiceError("%s exception raised making a digest "
                                        "of the input passphrase: %s" % 
                                        (e.__class__, e))
        else:
            passwd = passphrase

        dbEngine = create_engine(self.connectionString)
        connection = dbEngine.connect()
        
        try:
            queryInputs = dict(username=username, password=passwd)
            query = Template(self.sqlQuery).substitute(queryInputs)
            result = connection.execute(query)
            if not result.rowcount:
                raise AuthNServiceInvalidCredentials()
        finally:
            connection.close()
            