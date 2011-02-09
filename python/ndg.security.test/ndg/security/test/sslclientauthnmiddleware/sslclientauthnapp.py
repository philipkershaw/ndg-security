import logging
logging.basicConfig(level=logging.DEBUG)
import os
from os.path import dirname, abspath, join

from ndg.security.server.wsgi.apploader import AppLoaderMiddleware

def application(environ, start_response):
    status = '200 OK'
    output = 'Access allowed to this URL'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]

def app_factory(app_conf, **local_conf):
    return application

from ndg.security.test import BaseTestCase

# Initialize environment for unit tests
if BaseTestCase.configDirEnvVarName not in os.environ:
    os.environ[BaseTestCase.configDirEnvVarName] = \
                            join(dirname(abspath(dirname(__file__))), 'config')

# Initialize environment for unit tests
if 'NDGSEC_SSLCLNTAUTHN_UNITTEST_DIR' not in os.environ:
    os.environ['NDGSEC_SSLCLNTAUTHN_UNITTEST_DIR'] = \
                                    os.path.abspath(os.path.dirname(__file__))
                                    
if __name__ == '__main__':
    import sys
    from paste.httpserver import serve

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 7000
        
    cfgFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'test.ini')
    
    sslPEM = os.environ['NDGSEC_SSLCLNTAUTHN_UNITTEST_DIR']+'/localhost.pem'
    app = AppLoaderMiddleware(configFilePath=cfgFilePath)
    serve(app, host='0.0.0.0', port=port, ssl_pem=sslPEM)
