#!/usr/bin/env python
"""NDG Security test harness for security web services middleware stack

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from os import path
import optparse 
     
from OpenSSL import SSL
from OpenSSL import crypto 
from paste.deploy import loadapp
from paste.script.util.logging_config import fileConfig

from ndg.security.server.utils.paste_utils import PasteDeployAppServer
from ndg.security.test.unit import BaseTestCase

   
class OpenSSLVerifyCallbackMiddleware(object):
    """Set peer certificate retrieved from PyOpenSSL SSL context callback in
    environ dict SSL_CLIENT_CERT item
    
    FOR TESTING PURPOSES ONLY - IT IS NOT THREAD SAFE
    """
    def __init__(self, app):
        self._app = app
        self.ssl_client_cert = None
        
    def createSSLCallback(self):
        """Make a SSL Context callback function and return it to the caller"""
        def _callback(conn, x509, errnum, errdepth, ok):
            if errdepth == 0:
                self.ssl_client_cert = crypto.dump_certificate(
                                                    crypto.FILETYPE_PEM, x509)
            return ok
        
        return _callback
        
    def __call__(self, environ, start_response):
        """Set the latest peer SSL client certificate from the SSL callback
        into environ SSL_CLIENT_CERT key"""
        if self.ssl_client_cert:
            environ['SSL_CLIENT_CERT'] = self.ssl_client_cert
        self.ssl_client_cert = None
        return self._app(environ, start_response)
    

class ApacheSSLVariablesMiddleware(object):
    """Simulate Apache SSL environment setting relevant environ variables"""
    def __init__(self, app):
        self._app = app
                                 
    def __call__(self, environ, start_response):
        environ['HTTPS'] = '1'
        return self._app(environ, start_response)

       
INI_FILENAME = 'securityservices.ini'

# To start run 
# $ paster serve services.ini or run this file as a script, see
# $ ./securityservicesapp.py -h
if __name__ == '__main__':    
    cfgFilePath = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME) 
     
    defCertFilePath = path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 
                                'pki', 
                                'localhost.crt')
    defPriKeyFilePath = path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 
                                  'pki', 
                                  'localhost.key')
        
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=7443,
                      type='int',
                      help="port number to run under")

    parser.add_option("-s",
                      "--with-ssl",
                      dest="withSSL",
                      default='True',
                      help="Run with SSL")

    parser.add_option("-c",
                      "--cert-file",
                      dest='certFilePath',
                      default=defCertFilePath,
                      help="SSL Certificate file")

    parser.add_option("-k",
                      "--private-key-file",
                      default=defPriKeyFilePath,
                      dest='priKeyFilePath',
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="configFilePath",
                      default=cfgFilePath,
                      help="Configuration file path")
    
    opt = parser.parse_args()[0]
    cfgFilePath = path.abspath(opt.configFilePath)
    
    if opt.withSSL.lower() == 'true':
        
        ssl_context = SSL.Context(SSL.SSLv23_METHOD)
        ssl_context.set_options(SSL.OP_NO_SSLv2)
    
        ssl_context.use_privatekey_file(opt.priKeyFilePath)
        ssl_context.use_certificate_file(opt.certFilePath)
        
        ssl_context.load_verify_locations(None, BaseTestCase.CACERT_DIR)
        ssl_context.set_verify_depth(9)
        
        # Load the application from the Paste ini file configuration        
        fileConfig(cfgFilePath, defaults={'here': path.dirname(cfgFilePath)})
        app = loadapp('config:%s' % cfgFilePath)
        
        # Wrap the application in middleware to set the SSL client certificate 
        # obtained from the SSL handshake in environ                
        app = OpenSSLVerifyCallbackMiddleware(app)
        _callback = app.createSSLCallback()
        
        # Wrap in middleware to simulate Apache environment
        app = ApacheSSLVariablesMiddleware(app)
        
        ssl_context.set_verify(SSL.VERIFY_PEER, _callback)
        server = PasteDeployAppServer(app=app, 
                                      port=opt.port,
                                      ssl_context=ssl_context) 
    else:
        ssl_context = None

        server = PasteDeployAppServer(cfgFilePath=cfgFilePath, 
                                      port=opt.port,
                                      ssl_context=ssl_context) 
    server.start()

