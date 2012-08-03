'''
Created on Aug 3, 2012

@author: philipkershaw
'''
#!/usr/bin/env python
"""Test script to run MyProxy web service interface in the Paster web 
application server.
"""
__author__ = "P J Kershaw"
__date__ = "26/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
#import sys
from os import path
#from OpenSSL import SSL
#
#from myproxy.ws.test.server_utils import PasteDeployAppServer
#
THIS_DIR = path.abspath(path.dirname(__file__))
INI_FILENAME = 'myproxywsgi.ini'
ini_filepath = path.join(THIS_DIR, INI_FILENAME) 
#SSLCERT_FILEPATH = path.join(THIS_DIR, 'localhost.crt')
#SSLKEY_FILEPATH = path.join(THIS_DIR, 'localhost.key')
#PORTNUM = 7443
#WITH_SSL = True # Set to False to run over HTTP
#
#if __name__ == "__main__":
#    # Provide a port number as command line argument or accept the default
#    # PORTNUM
#    if len(sys.argv) > 1:
#        port = sys.argv[1]
#    else:
#        port = PORTNUM
#        
#    if WITH_SSL:
#        ssl_context = SSL.Context(SSL.SSLv23_METHOD)
#        ssl_context.set_options(SSL.OP_NO_SSLv2)
#    
#        ssl_context.use_privatekey_file(SSLKEY_FILEPATH)
#        ssl_context.use_certificate_file(SSLCERT_FILEPATH)
#    else:
#        ssl_context = None
#        
#    server = PasteDeployAppServer(ssl_context=ssl_context, 
#                                  cfgFilePath=ini_filepath, 
#                                  port=port, 
#                                  withLoggingConfig=False) 
#    try:   
#        server.start()   
#    except KeyboardInterrupt:
#        sys.exit(0) 
from paste.script.serve import ServeCommand

ServeCommand("serve").run([ini_filepath])
