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
    TEST_CONFIG_DIR_VARNAME = 'NDGSEC_TEST_CONFIG_DIR'

    
    NDGSEC_UNITTESTS_DISABLE_THREAD_SERVICES_ENVVAR = \
        'NDGSEC_UNITTESTS_DISABLE_THREAD_SERVICES'
    
    _disableServiceStartup = lambda self: bool(os.environ.get(
        BaseTestCase.NDGSEC_UNITTESTS_DISABLE_THREAD_SERVICES_ENVVAR))
    
    disableServiceStartup = property(fget=_disableServiceStartup,
                                     doc="Stop automated start-up of services "
                                         "for unit tests")
    
    NDGSEC_TEST_CONFIG_DIR = os.environ.get(TEST_CONFIG_DIR_VARNAME, 
                                            TEST_CONFIG_DIR)
    
    CACERT_DIR = os.path.join(NDGSEC_TEST_CONFIG_DIR, 'ca')
    PKI_DIR = os.path.join(NDGSEC_TEST_CONFIG_DIR, 'pki')
    
    def __init__(self, *arg, **kw):
        if BaseTestCase.TEST_CONFIG_DIR_VARNAME not in os.environ:
            os.environ[BaseTestCase.TEST_CONFIG_DIR_VARNAME] = TEST_CONFIG_DIR
                
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
        
    def __del__(self):
        """Stop any services started with the addService method"""
        if hasattr(self, 'services'):
            for service in self.services:
                service.terminateThread()

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


