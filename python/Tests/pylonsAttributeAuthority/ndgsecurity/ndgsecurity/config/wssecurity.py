import logging
log = logging.getLogger(__name__)

from ZSI.parse import ParsedSoap
from ZSI.writer import SoapWriter
from ndg.security.common.wsSecurity import SignatureHandler

class SignatureMiddleware(object):
    def __init__(self, app, app_conf):
        self.app = app
        pass
    
    def __call__(self, environ, start_response):

        ps = ParsedSoap(soapIn)
        self.signatureHandler.sign(ps)
        return self.app(environ, start_response)
    
class SignatureVerificationMiddleware(object):
    def __init__(self, app, app_conf):
        log.debug("SignatureVerificationMiddleware.__init__ ...")
        self.app = app
        self.signatureHandler = SignatureHandler(
                                        cfg=app_conf.get('wsseCfgFilePath'))
    
    def __call__(self, environ, start_response):
        
        soapIn = environ['wsgi.input'].getvalue()
        log.debug("Verifying signature...")
        
        ps = ParsedSoap(soapIn)
        self.signatureHandler.verify(ps)
        return self.app(environ, start_response)