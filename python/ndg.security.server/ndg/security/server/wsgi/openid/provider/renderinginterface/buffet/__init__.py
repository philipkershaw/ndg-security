"""NDG Security Pylons Buffet based Rendering Interface for 
OpenIDProviderMiddleware

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "14/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import httplib
from pylons.templating import Buffet

# Rendering classes for OpenID Provider must derive from generic render 
# interface
from ndg.security.server.wsgi.openid.provider import RenderingInterface, \
    AuthNInterfaceConfigError

# Boiler plate to create renderer
class OpenIDProviderRenderingBuffet(Buffet):
    def _update_names(self, ns):
        return ns

class BuffetRendering(RenderingInterface):
    """Provide Templating for OpenID Provider Middleware via Buffet
    class"""

    propNames = (
        'templateType', 
        'templateRoot',
        'baseURL',
        'leftLogo',
        'leftAlt',
        'ndgLink',
        'ndgImage',
        'disclaimer',
        'stfcLink',
        'stfcImage',
        'helpIcon',
    )
        
    def __init__(self, *arg, **opt):
        '''Extend RenderingInterface to include config and set-up for Buffet
        object
        
        @type *arg: tuple
        @param *arg: RenderingInterface parent class arguments
        @type **opt: dict
        @param **opt: additional keywords to set-up Buffet rendering'''
        super(BuffetRendering, self).__init__(*arg, **opt)
        
        try:
            for i in opt:
                setattr(self, i, opt[i])
        except KeyError, e:
            raise AuthNInterfaceConfigError("Missing property: %s" % e)   
         
        self._buffet = OpenIDProviderRenderingBuffet(self.templateType, 
                                            template_root=self.templateRoot)
        
        self.title = ''
        self.xml = ''
        self.headExtras = ''
        self.loginStatus = True
        
    def _render(self, templateName, c=None, **kw):
        '''Wrapper for Buffet.render'''
        if c is None:
            c = self
            
        kw['c'] = c
        
        rendering = self._buffet.render(template_name=templateName, 
                                        namespace=kw)
        return rendering
    
    def login(self, environ, start_response, success_to=None, fail_to=None, 
              msg=''):
        """Set-up template for OpenID Provider Login"""
        self.title = "OpenID Login"
        self.success_to = success_to or self.urls['url_mainpage']
        self.fail_to = fail_to or self.urls['url_mainpage'] 
        self.xml = msg
        
        response = self._render('ndg.security.login')
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response
       
        
    def mainPage(self, environ, start_response):
        """Set-up template for OpenID Provider Login"""
        self.title = "OpenID Provider"
        self.headExtras = '<meta http-equiv="x-xrds-location" content="%s"/>'%\
                        self.urls['url_serveryadis']
    
        response = self._render('ndg.security.mainPage')
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response

    def identityPage(self, environ, start_response):
        """Render the user's Identity page"""
        path = environ['PATH_INFO'].rstrip('/')
        idPath = self.urls['url_id'].replace(self.base_url, '')
        userIdentifier = path[len(idPath)+1:]
        if not userIdentifier:
            h.redirect_to(self.urls['url_mainpage'])
            
        self.title = "OpenID Identity Page"
                        
        link_tag = '<link rel="openid.server" href="%s"/>' % \
                    self.urls['url_openidserver']
              
        yadis_loc_tag = '<meta http-equiv="x-xrds-location" content="%s"/>' % \
            (self.urls['url_yadis']+'/'+userIdentifier)
            
        self.headExtras = link_tag + yadis_loc_tag
        identityURL = self.base_url + path
        self.xml = "<b><pre>%s</pre></b>" % identityURL
        
        response = self._render('ndg.security.identityPage')    
        start_response("200 OK", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response

   
    def decidePage(self, environ, start_response, oidRequest):
        """Handle user interaction required before final submit back to Relying
        Party"""
        self.title = 'Approve OpenID Request?'
        self.trust_root = oidRequest.trust_root
        self.oidRequest = oidRequest
        self.environ = environ
        
        response = self._render('ndg.security.decidePage')
        start_response("200 OK", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response

        
    def errorPage(self, environ, start_response, msg, code=500):
        '''Display error information'''
        self.title = 'Error with OpenID Provider'
        self.xml = msg
        response = self._render('ndg.security.error')
        start_response('%d %s' % (code, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response
