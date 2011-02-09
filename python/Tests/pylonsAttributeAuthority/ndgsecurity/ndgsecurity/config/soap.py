"""NDG Security SOAP Service Middleware

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "27/05/08"
__copyright__ = "(C) 2008 STFC & NERC"
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ZSI import EvaluateException, ParseException
from ZSI.parse import ParsedSoap
from ZSI.writer import SoapWriter
from ZSI import fault

from ZSI.ServiceContainer import ServiceSOAPBinding

class SOAPMiddleware(object):
       
    def __init__(self, app, app_conf, **kw):
        log.debug("SOAPMiddleware.__init__ ...")
        self.app = app
        
        self.app_conf = app_conf
        self.app_conf.update(kw)
        
        if 'ServiceSOAPBinding' not in self.app_conf:
            self.app_conf['ServiceSOAPBinding'] = ServiceSOAPBinding
            
        if 'pathInfo' not in self.app_conf:
            self.app_conf['pathInfo'] = '/'
            
    def __call__(self, environ, start_response):
        log.debug("SOAPMiddleware.__call__")
        
        # Apply filter for calls
        if not environ['PATH_INFO'].startswith(self.app_conf['pathInfo']):
            return self.app(environ, start_response)
        
        soapIn = environ['wsgi.input'].getvalue()
        log.debug("SOAP Request")
        log.debug("_"*80)
        log.debug(soapIn)
        log.debug("_"*80)
        
        ps = ParsedSoap(soapIn)
        method = getattr(self.app_conf['ServiceSOAPBinding'], 
                         'soap_%s' % environ['HTTP_SOAPACTION'].strip('"'))
        
        try:
            req, resp = method(ps)
        except Exception, e:
            self._writeFault(req, resp)
        
        sw = SoapWriter()
        sw.serialize(resp)
        
        soapOut = str(sw)
        
        log.debug("SOAP Response")
        log.debug("_"*80)
        log.debug(soapOut)
        log.debug("_"*80)
#                
#        if soap is not None:
#            return self._writeResponse(request, soap)
        self.app(environ, start_response)
        start_response("200 OK", [('Content-type', 'text/xml')])
        return soapOut 
