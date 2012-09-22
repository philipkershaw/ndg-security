'''
Created on Sep 22, 2012

@author: philipkershaw
'''
import logging
log = logging.getLogger(__name__)
from datetime import datetime

from OpenSSL import crypto
from paste.httpexceptions import HTTPUnauthorized

from myproxy.ws.server.wsgi.httpbasicauth import HttpBasicAuthMiddleware


class ClientRegisterMiddlewareError(Exception):
    '''Base class for Client Register exceptions'''
    
    
class ClientRegisterMiddlewareConfigError(ClientRegisterMiddlewareError):
    '''Parse error for Client Register config'''
    
    
class ClientRegisterMiddleware(object):
    '''Whitelist client requests based on SSL client certificate and username
    passed in HTTP basic auth header
    '''
    CLIENT_REGISTER_OPT_PREFIX = 'client_register.'
    DN_SUB_OPTNAME = 'dn'
    USERS_SUB_OPTNAME = 'users'
    
    def __init__(self, app):
        self.app = app
        self.client_register = {}
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix='client_register.',
                           **app_conf):
        obj = cls(app)
        
        # Parse client register.  This has the form of a list of clients and 
        # the usernames for which they can get a delegation e.g.
        # 
        # client_register.0.dn = /O=NDG/OU=Security/CN=delegatee.somewhere.ac.uk
        # client_register.0.users = another jbloggs jdoe
        # client_register.1.dn = /O=STFC/OU=CEDA/CN=delegatee.ceda.ac.uk
        # client_register.1.users = asmith 
        # 
        # would result in:
        #
        # client_register = {'/O=NDG/OU=Security/CN=delegatee.somewhere.ac.uk':
        #                    ['another', 'jbloggs', 'jdoe'],
        #                   '/O=STFC/OU=CEDA/CN=delegatee.ceda.ac.uk':
        #                    ['asmith']}
        dn_lookup = {}
        users_lookup = {}
        for optname, val in app_conf:
            if optname.startswith(prefix):
                identifier, sub_optname = optname.split('.')[:-2]
                                    
                if sub_optname == 'dn':
                    if sub_optname in dn_lookup:
                        raise ClientRegisterMiddlewareConfigError(
                                '%r duplicate option name found' % optname)
                        
                    dn_lookup[identifier] = sub_optname
                    
                elif sub_optname == 'users':
                    users_lookup[identifier] = val.split()
                    
                else:
                    raise ClientRegisterMiddlewareConfigError(
                        '%r option name not recognised' % optname)
                    
        # Match up DNs and usernames
        for identifier, dn in dn_lookup.items():
            obj.client_register[dn] = users_lookup.get(identifier, [])  

        return obj
        
    def __call__(self, environ, start_response):
        
        username = HttpBasicAuthMiddleware.parse_credentials(environ)[0]
        cert = self._parse_cert(environ)
        if (cert is not None and 
            self.is_valid_client_cert(cert) and
            self.check_client_register(cert, username)):
            
            return self.app(environ, start_response)
        else:
            raise HTTPUnauthorized()
        
    def _parse_cert(self, environ):
        '''Parse client certificate from environ'''
        pem_cert = environ.get(self.sslClientCertKeyName)
        if pem_cert is None:
            return None
        
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        return cert

    @staticmethod
    def _is_cert_expired(cert):
        '''Check if input certificate has expired
        @param cert: X.509 certificate
        @type cert: OpenSSL.crypto.X509
        @return: true if expired, false otherwise
        @rtype: bool
        '''
        notAfter = cert.get_notAfter()
        dtNotAfter = datetime.strptime(notAfter, '%Y%m%d%H%M%S%fZ')       
        dtNow = datetime.utcNow()
        
        return dtNotAfter < dtNow
    
    @classmethod
    def is_valid_client_cert(cls, cert):
        '''Check certificate time validity
        
        TODO: allow verification against CA certs - current assumption is 
        that Apache config performs this task!
        '''
        return cls._is_cert_expired(cert)
    
    def check_client_register(self, cert, username):
        '''Check client identity against registry'''
        dn = self.__class__.cert_dn(cert)
        if dn not in self.client_register:
            log.info('Client certificate DN %r not found in client register',
                     dn)
            raise HTTPUnauthorized()
        
        if username not in self.client_register[dn]:
            log.info('No match for user %r and client certificate DN %r '
                     ' in client register', username, dn)            
            raise HTTPUnauthorized()
        
    @staticmethod
    def cert_dn(cert):
        subject = cert.get_subject()
        components = subject.get_components()
        cert_dn = '/'+ '/'.join(['%s=%s' % i for i in components])
        return cert_dn
        