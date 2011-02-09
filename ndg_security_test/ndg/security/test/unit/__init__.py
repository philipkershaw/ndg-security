"""NDG Security unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "14/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: __init__.py 4840 2009-01-19 13:59:08Z pjkersha $'

import unittest
import logging
import socket
logging.basicConfig()
log = logging.getLogger(__name__)

import os
from os.path import expandvars, join, dirname, abspath

try:
    from hashlib import md5
except ImportError:
    # Allow for < Python 2.5
    from md5 import md5


TEST_CONFIG_DIR = join(abspath(dirname(dirname(__file__))), 'config')

mkDataDirPath = lambda file:join(TEST_CONFIG_DIR, file)

from ndg.security.common.X509 import X500DN
from ndg.security.test.unit.wsgi import PasteDeployAppServer

try:
    from sqlalchemy import (create_engine, MetaData, Table, Column, Integer, 
                            String)
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    
    sqlAlchemyInstalled = True
except ImportError:
    sqlAlchemyInstalled = False
    
    
class BaseTestCase(unittest.TestCase):
    '''Convenience base class from which other unit tests can extend.  Its
    sets the generic data directory path'''
    configDirEnvVarName = 'NDGSEC_TEST_CONFIG_DIR'
    
    SITEA_ATTRIBUTEAUTHORITY_PORTNUM = 5000
    SITEB_ATTRIBUTEAUTHORITY_PORTNUM = 5100
    
    SITEA_ATTRIBUTEAUTHORITY_URI = 'http://localhost:%s/AttributeAuthority' % \
                                    SITEA_ATTRIBUTEAUTHORITY_PORTNUM
                                    
    SITEB_ATTRIBUTEAUTHORITY_URI = 'http://localhost:%s/AttributeAuthority' % \
                                    SITEB_ATTRIBUTEAUTHORITY_PORTNUM
                                    
    SITEA_ATTRIBUTEAUTHORITY_SAML_URI = \
        'http://localhost:%s/AttributeAuthority/saml' % \
                                    SITEA_ATTRIBUTEAUTHORITY_PORTNUM
                                    
    SITEB_ATTRIBUTEAUTHORITY_SAML_URI = \
        'http://localhost:%s/AttributeAuthority/saml' % \
                                    SITEB_ATTRIBUTEAUTHORITY_PORTNUM
                                    
    SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM = 5443
    SITEA_SSL_ATTRIBUTEAUTHORITY_SAML_URI = \
        'https://localhost:%d/AttributeAuthority/saml' % \
                                    SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM
    SSL_CERT_DN = "/C=UK/ST=Oxfordshire/O=BADC/OU=Security/CN=localhost"
                                    
    SITEA_SAML_ISSUER_NAME = "/O=Site A/CN=Attribute Authority"
    
    SESSIONMANAGER_PORTNUM = 5500
    
    NDGSEC_UNITTESTS_DISABLE_THREAD_SERVICES_ENVVAR = \
        'NDGSEC_UNITTESTS_DISABLE_THREAD_SERVICES'
    
    _disableServiceStartup = lambda self: bool(os.environ.get(
        BaseTestCase.NDGSEC_UNITTESTS_DISABLE_THREAD_SERVICES_ENVVAR))
    
    disableServiceStartup = property(fget=_disableServiceStartup,
                                     doc="Stop automated start-up of services "
                                         "for unit tests")
    
    NDGSEC_TEST_CONFIG_DIR = os.environ.get(configDirEnvVarName, 
                                            TEST_CONFIG_DIR)
    
    CACERT_DIR = os.path.join(NDGSEC_TEST_CONFIG_DIR, 'ca')
    PKI_DIR = os.path.join(NDGSEC_TEST_CONFIG_DIR, 'pki')
    SSL_CERT_FILEPATH = os.path.join(PKI_DIR, 'localhost.crt')
    SSL_PRIKEY_FILEPATH = os.path.join(PKI_DIR, 'localhost.key')
    
    # Test database set-up
    DB_FILENAME = 'user.db'
    DB_FILEPATH = join(NDGSEC_TEST_CONFIG_DIR, DB_FILENAME)
    DB_CONNECTION_STR = 'sqlite:///%s' % DB_FILEPATH
    
    USERNAME = 'pjk'
    PASSWORD = 'testpassword'
    MD5_PASSWORD = md5(PASSWORD).hexdigest()
    
    OPENID_URI_STEM = 'https://localhost:7443/openid/'
    OPENID_IDENTIFIER = 'philip.kershaw'
    OPENID_URI = OPENID_URI_STEM + OPENID_IDENTIFIER
    
    FIRSTNAME = 'Philip'
    LASTNAME = 'Kershaw'
    EMAILADDRESS = 'pjk@somewhere.ac.uk'
    
    ATTRIBUTE_NAMES = (
        "urn:siteA:security:authz:1.0:attr",
    )

    ATTRIBUTE_VALUES = (
        'urn:siteA:security:authz:1.0:attr:postdoc',
        'urn:siteA:security:authz:1.0:attr:staff', 
        'urn:siteA:security:authz:1.0:attr:undergrad', 
        'urn:siteA:security:authz:1.0:attr:coapec',
        'urn:siteA:security:authz:1.0:attr:rapid'
    )
    N_ATTRIBUTE_VALUES = len(ATTRIBUTE_VALUES)
    
    VALID_REQUESTOR_IDS = (
        X500DN.fromString("/O=Site A/CN=Authorisation Service"), 
        X500DN.fromString("/O=Site B/CN=Authorisation Service"),
        X500DN.fromString('/CN=test/O=NDG/OU=BADC')
    )
    
    SSL_PEM_FILENAME = 'localhost.pem'
    SSL_PEM_FILEPATH = mkDataDirPath(os.path.join('pki', SSL_PEM_FILENAME))
    
    def __init__(self, *arg, **kw):
        if BaseTestCase.configDirEnvVarName not in os.environ:
            os.environ[BaseTestCase.configDirEnvVarName] = TEST_CONFIG_DIR
                
        unittest.TestCase.__init__(self, *arg, **kw)
        self.services = []
        
    def addService(self, *arg, **kw):
        """Utility for setting up threads to run Paste HTTP based services with
        unit tests
        
        @param cfgFilePath: ini file containing configuration for the service
        @type cfgFilePath: basestring
        @param port: port number to run the service from
        @type port: int
        """
        if self.disableServiceStartup:
            return
        
        withSSL = kw.pop('withSSL', False)
        if withSSL:
            from OpenSSL import SSL
            
            certFilePath = mkDataDirPath(os.path.join('pki', 'localhost.crt'))
            priKeyFilePath = mkDataDirPath(os.path.join('pki', 'localhost.key'))
            
            kw['ssl_context'] = SSL.Context(SSL.SSLv23_METHOD)
            kw['ssl_context'].set_options(SSL.OP_NO_SSLv2)
        
            kw['ssl_context'].use_privatekey_file(priKeyFilePath)
            kw['ssl_context'].use_certificate_file(certFilePath)
            
        try:
            self.services.append(PasteDeployAppServer(*arg, **kw))
            self.services[-1].startThread()
            
        except socket.error:
            pass

    def startAttributeAuthorities(self, withSSL=False, port=None):
        """Serve test Attribute Authorities to test against"""
        self.startSiteAAttributeAuthority(withSSL=withSSL, port=port)
        self.startSiteBAttributeAuthority(withSSL=withSSL, port=port)
        
    def startSiteAAttributeAuthority(self, withSSL=False, port=None):
        siteACfgFilePath = mkDataDirPath(join('attributeauthority', 
                                              'sitea', 
                                              'site-a.ini'))
        self.addService(cfgFilePath=siteACfgFilePath, 
                        port=port or BaseTestCase.SITEA_ATTRIBUTEAUTHORITY_PORTNUM,
                        withSSL=withSSL)
        
    def startSiteBAttributeAuthority(self, withSSL=False, port=None):
        siteBCfgFilePath = mkDataDirPath(join('attributeauthority',
                                              'siteb', 
                                              'site-b.ini'))
        self.addService(cfgFilePath=siteBCfgFilePath, 
                        port=port or BaseTestCase.SITEB_ATTRIBUTEAUTHORITY_PORTNUM,
                        withSSL=withSSL)        

    def startSessionManager(self):
        """Serve test Session Manager service"""
        cfgFilePath = mkDataDirPath(join('sessionmanager', 
                                         'session-manager.ini'))
        self.addService(cfgFilePath=cfgFilePath, 
                        port=BaseTestCase.SESSIONMANAGER_PORTNUM)
        

    def __del__(self):
        """Stop any services started with the addService method"""
        if hasattr(self, 'services'):
            for service in self.services:
                service.terminateThread()
 
    @classmethod
    def initDb(cls):
        """Wrapper to _createDb - Create database only if it doesn't already 
        exist"""
        if not os.path.isfile(cls.DB_FILEPATH):
            cls._createDb()
        
    @classmethod  
    def _createDb(cls):
        """Create a test SQLite database with SQLAlchemy for use with unit 
        tests
        """
        log.debug("Creating database for %r ..." % cls.__name__)
        
        if not sqlAlchemyInstalled:
            raise NotImplementedError("SQLAlchemy must be installed in order "
                                      "for this method to be implemented")
            
        db = create_engine(cls.DB_CONNECTION_STR)
        
        metadata = MetaData()
        usersTable = Table('users', metadata,
                           Column('id', Integer, primary_key=True),
                           Column('username', String),
                           Column('md5password', String),
                           Column('openid', String),
                           Column('openid_identifier', String),
                           Column('firstname', String),
                           Column('lastname', String),
                           Column('emailaddress', String))
        
        attributesTable = Table('attributes', metadata,
                                Column('id', Integer, primary_key=True),
                                Column('openid', String),
                                Column('attributename', String))
        metadata.create_all(db)
        
        class User(declarative_base()):
            __tablename__ = 'users'
        
            id = Column(Integer, primary_key=True)
            username = Column('username', String(40))
            md5password = Column('md5password', String(64))
            openid = Column('openid', String(128))
            openid_identifier = Column('openid_identifier', String(40))
            firstname = Column('firstname', String(40))
            lastname = Column('lastname', String(40))
            emailAddress = Column('emailaddress', String(40))
        
            def __init__(self, username, md5password, openid, openid_identifier, 
                         firstname, lastname, emailaddress):
                self.username = username
                self.md5password = md5password
                self.openid = openid
                self.openid_identifier = openid_identifier
                self.firstname = firstname
                self.lastname = lastname
                self.emailAddress = emailaddress
        
        class Attribute(declarative_base()):
            __tablename__ = 'attributes'
        
            id = Column(Integer, primary_key=True)
            openid = Column('openid', String(128))
            attributename = Column('attributename', String(40))
        
            def __init__(self, openid, attributename):
                self.openid = openid
                self.attributename = attributename

        Session = sessionmaker(bind=db)
        session = Session()
        
        attributes = [Attribute(cls.OPENID_URI, attrVal)
                      for attrVal in cls.ATTRIBUTE_VALUES]
        session.add_all(attributes)
           
        user = User(cls.USERNAME, 
                    cls.MD5_PASSWORD,
                    cls.OPENID_URI,
                    cls.OPENID_IDENTIFIER,
                    cls.FIRSTNAME,
                    cls.LASTNAME,
                    cls.EMAILADDRESS)
        
        session.add(user)
        session.commit() 


def _getParentDir(depth=0, path=dirname(__file__)):
    """
    @type path: basestring
    @param path: directory path from which to get parent directory, defaults
    to dir of this module
    @rtype: basestring
    @return: parent directory at depth levels up from the current path
    """
    for i in range(depth):
        path = dirname(path)
    return path


