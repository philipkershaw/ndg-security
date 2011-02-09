"""WSGI Middleware to set an Attribute Authority instance in tyhe WSGI environ

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import os
import warnings

from ndg.security.server.attributeauthority import AttributeAuthority
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase

_soapBindingMiddlewareImportError = False
try:
    from ndg.security.server.wsgi.zsi import SOAPBindingMiddleware
except ImportError, e:
    warnings.warn("SOAPBindingMiddleware import error: %s" % e)
    _soapBindingMiddlewareImportError = True


class AttributeAuthorityMiddleware(NDGSecurityMiddlewareBase):
    '''WSGI to add an NDG Security Attribute Authority in the environ.  This
    enables multiple WSGi filters to access the same underlying Attribute
    Authority instance e.g. provide SAML SOAP and WSDL SOAP based interfaces
    to the same Attribute Authority
    '''
    DEFAULT_KEYNAME = 'ndg.security.server.wsgi.attributeauthority'
    ENVIRON_KEYNAME_CFG_OPTNAME = 'environKeyName'
    
    DEFAULT_ATTR_QUERY_IFACE_KEYNAME = \
        'ndg.security.server.wsgi.attributeauthority.attributeQuery'
    ENVIRON_KEYNAME_ATTR_QUERY_IFACE_CFG_OPT_NAME = \
        'environKeyNameAttributeQueryInterface'
        
    def __init__(self, app):
        '''Set-up an Attribute Authority instance
        '''
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        self._app = app
        self.__aa = None
        self.__attributeQuery = None
        self.__keyName = None
        self.__attributeQueryKeyName = None

    def initialise(self, global_conf, prefix='attributeauthority.',
                   **app_conf):
        """Set-up Attribute authority middleware using a Paste app factory 
        pattern.  Overloaded base class method to enable custom settings from 
        app_conf
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        # Set key name for attribute authority set in environ
        environKeyOptName = prefix + \
                    AttributeAuthorityMiddleware.ENVIRON_KEYNAME_CFG_OPTNAME
                    
        self.keyName = app_conf.pop(environKeyOptName,
                                AttributeAuthorityMiddleware.DEFAULT_KEYNAME)

        attrQueryIfaceEnvironKeyOptName = prefix + \
            AttributeAuthorityMiddleware.\
            ENVIRON_KEYNAME_ATTR_QUERY_IFACE_CFG_OPT_NAME
            
        self.attributeQueryKeyName = app_conf.pop(
            attrQueryIfaceEnvironKeyOptName,
            AttributeAuthorityMiddleware.DEFAULT_ATTR_QUERY_IFACE_KEYNAME)
        
        self.aa = AttributeAuthority.fromProperties(propPrefix=prefix,
                                                    **app_conf)
        self.attributeQuery = self.aa.samlAttributeQueryFactory()

    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        '''Wrapper to enable instantiation compatible with Paste Deploy
        filter application factory function signature
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        app = AttributeAuthorityMiddleware(app)
        app.initialise(global_conf, **app_conf)
        
        return app
    
    def __call__(self, environ, start_response):
        '''Set the Attribute Authority instantiated at initialisation in 
        environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: next application in the WSGI stack
        '''
        environ[self.keyName] = self.aa
        environ[self.attributeQueryKeyName] = self.attributeQuery
        return self._app(environ, start_response)
    
    def _get_aa(self):
        return self.__aa
    
    def _set_aa(self, val):
        if not isinstance(val, AttributeAuthority):
            raise TypeError('Expecting %r for "aa" attribute; got %r' %
                            (AttributeAuthority, type(val)))
        self.__aa = val
            
    aa = property(fget=_get_aa,
                  fset=_set_aa,
                  doc="Attribute Authority instance")

    def _getKeyName(self):
        return self.__keyName

    def _setKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "keyName" attribute; got %r' %
                            (basestring, type(val)))
        self.__keyName = val
        
    keyName = property(fget=_getKeyName, 
                       fset=_setKeyName, 
                       doc="Key name used to index Attribute Authority in "
                           "environ dictionary")

    def _get_attributeQueryKeyName(self):
        return self.__attributeQueryKeyName

    def _set_attributeQueryKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "attributeQueryKeyName" '
                            'attribute; got %r' % (basestring, type(val)))
        self.__attributeQueryKeyName = val
        
    attributeQueryKeyName = property(fget=_get_attributeQueryKeyName, 
                                     fset=_set_attributeQueryKeyName, 
                                     doc="Key name used to index Attribute "
                                         "Authority SAML attribute query "
                                         "function in environ dictionary")
    
    def _get_attributeQuery(self):
        return self.__attributeQuery

    def _set_attributeQuery(self, val):
        if not callable(val):
            raise TypeError('Expecting a callable for "attributeQuery" '
                            'attribute; got %r' % type(val))
        self.__attributeQuery = val
        
    attributeQuery = property(fget=_get_attributeQuery, 
                              fset=_set_attributeQuery, 
                              doc="Attribute Authority SAML attribute query "
                                  "function")


from ndg.security.server.zsi.attributeauthority import AttributeAuthorityWS

class AttributeAuthoritySOAPBindingMiddlewareConfigError(Exception):
    """Raise if a configuration problem is found"""
    
    
class AttributeAuthoritySOAPBindingMiddleware(NDGSecurityMiddlewareBase,
                                              AttributeAuthorityWS):
    """Inheritance from NDGSecurityMiddlewareBase provides a __call__
    implementation which sets a reference to environ as an object attribute.
    
    Inheritance from AttributeAuthorityWS enables preservation of the same
    SOAP callbacks but with the 
    ndg.security.server.attributeauthority.AttributeAuthority instance provided
    from environ
    
    @type DEFAULT_ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME: basestring
    @cvar DEFAULT_ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME: Key name used to index the 
    ndg.security.server.attributeauthority.AttributeAuthority instance in the 
    environ dictionary
    @type ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME_CFG_OPTNAME: basestring
    @cvar ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME_CFG_OPTNAME: configuration option name
    for the attribute authority environ key
    @type DEFAULT_ENVIRON_KEYNAME: basestring
    @cvar DEFAULT_ENVIRON_KEYNAME: default value for Key name used to index 
    THIS SOAP Service Binding middleware instance in the environ dictionary
    @type ENVIRON_KEYNAME_CFG_OPTNAME: basestring
    @cvar ENVIRON_KEYNAME_CFG_OPTNAME: configuration option name for this 
    middleware's environ key
    """
    DEFAULT_ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME = \
                "ndg.security.server.attributeauthority.AttributeAuthority"
    ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME_CFG_OPTNAME = \
                'attributeAuthorityEnvironKeyName'
    
    DEFAULT_ENVIRON_KEYNAME = ("ndg.security.server.wsgi.attributeauthority."
                               "AttributeAuthoritySOAPBindingMiddleware")
    ENVIRON_KEYNAME_CFG_OPTNAME = 'environKeyName'
    
    def __init__(self, app):
        """Don't call AttributeAuthorityWS.__init__ - AttributeAuthority 
        instance is provided via environ through upstream 
        AttributeAuthorityMiddleware
        """
        if _soapBindingMiddlewareImportError:
            raise ImportError("SOAPBindingMiddleware would not import, this "
                              "class is disabled.  Check warning messages.  "
                              "ZSI dependency may be installed")
            
        # Call this base class initialiser to set-up the environ attribute
        NDGSecurityMiddlewareBase.__init__(self, app, None)
        AttributeAuthorityWS.__init__(self)
        
        self.__keyName = None
        self.__attributeAuthorityKeyName = None
        
    def _getKeyName(self):
        return self.__keyName

    def _setKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "keyName" attribute; got %r' %
                            (basestring, type(val)))
        self.__keyName = val
        
    keyName = property(fget=_getKeyName, 
                       fset=_setKeyName, 
                       doc="Key name used to index THIS SOAP Service Binding "
                           "middleware instance in the environ dictionary")   

    def _getAttributeAuthorityKeyName(self):
        return self.__attributeAuthorityKeyName

    def _setAttributeAuthorityKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "attributeAuthorityKeyName" '
                            'attribute; got %r' %(basestring, type(val)))
        self.__attributeAuthorityKeyName = val
        
    attributeAuthorityKeyName = property(fget=_getAttributeAuthorityKeyName, 
                                         fset=_setAttributeAuthorityKeyName, 
                                         doc="Key name used to index the "
                                             "ndg.security.server.attribute"
                                             "authority.AttributeAuthority "
                                             "instance in the environ "
                                             "dictionary") 
             
    @classmethod
    def filter_app_factory(cls, app, global_conf, 
        attributeAuthoritySOAPBindingPrefix='attributeauthority.soapbinding.', 
        **app_conf):
        """Set-up Attribute Authority SOAP Binding middleware using a Paste app
        factory pattern.  Overloaded base class method to enable custom 
        settings from app_conf
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        # Generic Binding middleware intercepts the SOAP_ACTION set in environ
        # and maps it to the matching soap_{SOAP_ACTION} method from this class
        soapBindingApp = SOAPBindingMiddleware.filter_app_factory(app, 
                                                                  global_conf,
                                                                  **app_conf)
        
        # Make the SOAP Binding wrapper pick up this Attribute Authority
        # specific SOAP Binding
        optName = attributeAuthoritySOAPBindingPrefix + \
                cls.ENVIRON_KEYNAME_CFG_OPTNAME
        soapBindingApp.serviceSOAPBindingKeyName = app_conf.get(optName,
                                                cls.DEFAULT_ENVIRON_KEYNAME)
        
        # Instantiate this middleware and copy the environ key name setting for
        # the Attribute Authority Service SOAP Binding
        app = cls(soapBindingApp)
        app.keyName = soapBindingApp.serviceSOAPBindingKeyName
        
        # envrion key name for the 
        # ndg.security.server.attributeauthority.AttributeAuthority instance
        optName = attributeAuthoritySOAPBindingPrefix + \
                cls.ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME_CFG_OPTNAME
                
        app.attributeAuthorityKeyName = app_conf.get(optName,
                           cls.DEFAULT_ATTRIBUTE_AUTHORITY_ENVIRON_KEYNAME)

            
        # Extract local WS-Security signature verification filter
        optName = attributeAuthoritySOAPBindingPrefix + \
                            cls.WSSE_SIGNATURE_VERIFICATION_FILTER_ID_OPTNAME
        app.wsseSignatureVerificationFilterID = app_conf.pop(optName, None)
        if app.wsseSignatureVerificationFilterID is None:
            log.warning('No "%s" option was set in the input config' % 
                        cls.WSSE_SIGNATURE_VERIFICATION_FILTER_ID_OPTNAME)
        else:   
            log.info('Updated setting from "%s" option' % 
                     cls.WSSE_SIGNATURE_VERIFICATION_FILTER_ID_OPTNAME)
                    
        return app
 
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """Set a reference to self in environ for the SOAPBindingMiddleware 
        instance to pick up downstream
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        """

        environ[self.keyName] = self
        return self._app(environ, start_response)
    
    def soap_getAttCert(self, ps):
        '''Retrieve an Attribute Certificate
        
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: ndg.security.common.zsi.attributeauthority.AttributeAuthority_services_types.getAttCertResponse_Holder
        @return: response'''
        self._setAttributeAuthorityFromEnviron()
        return AttributeAuthorityWS.soap_getAttCert(self, ps)

    def soap_getHostInfo(self, ps):
        '''Get information about this host
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: response
        @return: response'''
        self._setAttributeAuthorityFromEnviron()
        return AttributeAuthorityWS.soap_getHostInfo(self, ps)
    
    def soap_getAllHostsInfo(self, ps):
        '''Get information about all hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: response object'''
        self._setAttributeAuthorityFromEnviron()
        return AttributeAuthorityWS.soap_getAllHostsInfo(self, ps)
    
    def soap_getTrustedHostInfo(self, ps):
        '''Get information about other trusted hosts
                
        @type ps: ZSI ParsedSoap
        @param ps: client SOAP message
        @rtype: tuple
        @return: response object'''
        self._setAttributeAuthorityFromEnviron()
        return AttributeAuthorityWS.soap_getTrustedHostInfo(self, ps)
    
    def _setAttributeAuthorityFromEnviron(self):
        self.aa = self.environ.get(self.attributeAuthorityKeyName)
        if self.aa is None:
            raise AttributeAuthoritySOAPBindingMiddlewareConfigError(
                                            'No "%s" key found in environ' % 
                                            self.attributeAuthorityKeyName)
