#!/usr/bin/env python
"""NDG Security test harness for authorisation middleware used to secure an
application

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - See top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"

   
def app_factory(globalConfig, **localConfig):
    '''AuthZTestMiddleware factory for Paste app pattern'''
    return AuthZTestMiddleware(None, globalConfig, **localConfig)

def filter_app_factory(app, globalConfig, **localConfig):
    '''AuthZTestMiddleware factory for Paste filter app pattern'''
    return AuthZTestMiddleware(app, globalConfig, **localConfig)

class AuthZTestMiddleware(object):
    """This class simulates the application to be secured by the NDG Security
    authorization middleware
    """
    method = {
"/": 'default',
"/test_401": "test_401",
"/test_403": "test_403",
"/test_securedURI": "test_securedURI",
"/test_accessDeniedToSecuredURI": "test_accessDeniedToSecuredURI"
    }
    header = """        <h1>Authorisation Integration Tests:</h1>
        <p>Test Authorisation middleware with no Session Manager running.
        See the authz/ integration test directory for a configuration including
        a Session Manager</p>
        <p>These tests use require the security services application to be
        running.  See securityserviceapp.py and securityservices.ini in the 
        authz_lite/ integration test directory.</p>
        <h2>To Run:</h2>
        <p>Try any of the links below.  When prompt for username and password,
        enter one of the sets of credentials from securityservices.ini
        openid.provider.authN.userCreds section.  The defaults are:
        </p>
        <p>pjk/testpassword</p>
        <p>another/testpassword</p>
        <p>The attributeinterface.py AttributeAuthority plugin is configured to
        grant access to 'pjk' for all URLs below apart from 
        'test_accessDeniedToSecuredURI'.  The 'another' account will be denied
        access from all URLs apart from 'test_401'</p>
"""

    def __init__(self, app, globalConfig, **localConfig):
        self.app = app
            
    def __call__(self, environ, start_response):
        
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif environ['PATH_INFO'] == '/logout':
            return self.default(environ, start_response)
        
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
        %s
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (AuthZTestMiddleware.header,
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default']),
       environ['REMOTE_USER'])
        
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = """<html>
    <head/>
    <body>
        <h1>Authorisation integration tests:</h1>
        <ul>%s</ul>
    </body>
</html>
""" % '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default'])

            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        return response

    def test_401(self, environ, start_response):
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <h1>Authenticated!</h1>
        <ul>%s</ul>
        <p>You are logged in.  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default'])

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
        """Trigger the Authorization middleware by returning a 403 Forbidden
        HTTP status code from this URI"""
        
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <h1>Authorised!</h1>
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % ('\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default']),
       environ['REMOTE_USER'])

            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = ("Authorization middleware is triggered because this "
                        "page returns a 403 Forbidden status.")
            start_response('403 Forbidden', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response

    def test_securedURI(self, environ, start_response):
        """To be secured, the Authorization middleware must have this URI in
        its policy"""
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <h1>Authorised for path [%s]!</h1>
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (environ['PATH_INFO'],
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default']),
       environ['REMOTE_USER'])


            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = ("Authorization middleware must have this URI in its "
                        "policy in order to secure it!")
            start_response('200 OK', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response


    def test_accessDeniedToSecuredURI(self, environ, start_response):
        """To be secured, the Authorization middleware must have this URI in
        its policy and the user must not have the required role as specified
        in the policy.  See ndg.security.test.config.attributeauthority.sitea
        for user role settings retrieved from the attribute authority"""
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <h1>Authorised for path [%s]!</h1>
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (environ['PATH_INFO'],
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default']),
       environ['REMOTE_USER'])


            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = ("Authorization middleware must have this URI in its "
                        "policy in order to secure it!")
            start_response('200 OK', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response
   
    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)
    
    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./securedapp.py [port #]
if __name__ == '__main__':
    import sys
    import os
    from os.path import dirname, abspath
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 7080
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 'securedapp.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)