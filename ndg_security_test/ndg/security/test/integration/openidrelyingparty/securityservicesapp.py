#!/usr/bin/env python
"""NDG Security test harness for authorisation middleware

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import os
from os.path import dirname, abspath, join

class AuthZTestMiddleware(object):
    method = {
"/": 'default',
"/test_401": "test_401",
"/test_403": "test_403",
"/test_securedURI": "test_securedURI"
    }

    def __init__(self, app, globalConfig, **localConfig):
        self.app = app
            
    def __call__(self, environ, start_response):
        
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "Authorisation integration tests: invalid URI"
            
    def default(self, environ, start_response):
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <p>Authenticated!</p>
        <p><a href="/logout">logout</a></p>
    </body>
</html>"""
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "Authorisation integration tests"
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        return response

    def test_401(self, environ, start_response):
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <p>Authenticated!</p>
        <p><a href="/logout">logout</a></p>
    </body>
</html>"""
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "Trigger OpenID Relying Party..."
            start_response('401 Unauthorized', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response

    def test_403(self, environ, start_response):
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <p>Authorised!</p>
        <p><a href="/logout">logout</a></p>
    </body>
</html>"""
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "Trigger AuthZ..."
            start_response('403 Forbidden', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response

    def test_securedURI(self, environ, start_response):
        response = "Access allowed"
        start_response('200 OK', 
                       [('Content-type', 'text/plain'),
                        ('Content-length', str(len(response)))])
        return response
    
def app_factory(globalConfig, **localConfig):
    return AuthZTestMiddleware(None, globalConfig, **localConfig)

def filter_app_factory(app, globalConfig, **localConfig):
    return AuthZTestMiddleware(app, globalConfig, **localConfig)
    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./serverapp.py [port #]
if __name__ == '__main__':
    import sys
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 6443
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 
                               'securityservices.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)