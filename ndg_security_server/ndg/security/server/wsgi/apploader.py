import os
from paste.deploy import loadapp

class AppLoaderMiddleware(object):
    def __init__(self, configFilePath=None):
        self._configFilePath = configFilePath or \
            os.environ.get('NDGSEC_WSGI_APPLOADER_CFGFILEPATH')
            
        self._app = loadapp('config:%s' % configFilePath)

    def __call__(self, environ, start_response):
        return self._app(environ, start_response)
