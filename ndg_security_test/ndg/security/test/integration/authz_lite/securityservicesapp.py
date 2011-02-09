#!/usr/bin/env python
"""NDG Security test harness for security web services middleware stack

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import os
from os.path import dirname, abspath, join
      
from OpenSSL import SSL

from ndg.security.test.unit import BaseTestCase, TEST_CONFIG_DIR
from ndg.security.test.unit.wsgi import PasteDeployAppServer

INI_FILEPATH = 'securityservices.ini'

os.environ['NDGSEC_INTEGRATION_TEST_DIR'] = os.path.dirname(os.path.dirname(
                                                                    __file__))
os.environ[BaseTestCase.configDirEnvVarName] = TEST_CONFIG_DIR

# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./securityservicesapp.py [port #]
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 7443
            
    # Initialise test user database
    from ndg.security.test.unit import BaseTestCase
    BaseTestCase.initDb()
    
    cfgFileName = INI_FILEPATH
    cfgFilePath = os.path.join(dirname(abspath(__file__)), cfgFileName)  
    
    certFilePath = os.path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 
                                'pki', 
                                'localhost.crt')
    priKeyFilePath = os.path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 
                                  'pki', 
                                  'localhost.key')
    
    ssl_context = SSL.Context(SSL.SSLv23_METHOD)
    ssl_context.set_options(SSL.OP_NO_SSLv2)

    ssl_context.use_privatekey_file(priKeyFilePath)
    ssl_context.use_certificate_file(certFilePath)

    server = PasteDeployAppServer(cfgFilePath=cfgFilePath, 
                                  port=port,
                                  ssl_context=ssl_context) 
    server.start()
