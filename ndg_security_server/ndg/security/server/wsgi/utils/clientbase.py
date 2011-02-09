"""NDG Security

Functionality for client interface to WSGI based applications.  

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "30/01/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

class WSGIClientBase(object):
    '''Base class for client interface to WSGI based applications.  The client 
    can access the service via a key in the WSGI environ dictionary or by 
    instantiating a proxy to some remote service.  By wrapping this choice,
    clients can potentially avoid calls over the wire to services that are
    otherwise available locally.  At the same time, the client can be 
    agnostic as to whether the call was made locally or over the network.
    '''

    defaultEnvironKeyName = ''
    
    def __init__(self, environKeyName=None, environ={}, **clientKw):
        """Initialise an interface to a service accessible either via a
        keyword to a WSGI environ dictionary or via a web service call
        
        @type environKeyName: basestring or None
        @param environKeyName: dict key reference to service object to be 
        invoked.  This may be set later using the environKeyName property
        or may be omitted altogether if the service is to be invoked via a
        web service call
        @type environ: dict
        @param environ: WSGI environment dictionary containing a reference to
        the service object.  This may not be known at instantiation of this
        class.  environ is not required if the service is to be invoked over
        a web service interface
        @type clientKw: dict
        @param clientKw: custom keywords to instantiate a web service client
        interface.  Derived classes are responsible for instantiating this
        from an extended version of this __init__ method.
        """
        
        self._environKeyName = environKeyName or \
                               WSGICLientBase.defaultEnvironKeyName
                        
        # Standard WSGI environment dict
        self._environ = environ   
        
        # Derived class could instantiate required client type if a 'uri'
        # key is set in clientKw    
        self._wsClient = None
        
    def _getWSClient(self):
        return getattr(self, '_wsClient', None)
    
    def _setWSClient(self, wsClient):
        self._wsClient = wsClient
    
    wsClient = property(fget=_getWSClient,
                        fset=_setWSClient, 
                        doc="Web service client to service to be invoked")
    
    def _getWSClientURI(self):
        return getattr(self.wsClient, 'uri', None)

    uri = property(fget=_getWSClientURI,
                   doc="URI for web service or None if no WS Client is set")

    def _setEnvironKeyName(self, keyName):
        if not isinstance(keyName, (None.__class__, basestring)):
            raise TypeError("environKeyName must be string or None type; got "
                            "%s" % keyName)
            
        self._environKeyName = keyName

    def _getEnvironKeyName(self):
        return self._environKeyName
    
    environKeyName = property(fget=_getEnvironKeyName,
                              fset=_setEnvironKeyName,
                              doc="key in environ dict holding reference to "
                                  "service to be invoked.  This may be None "
                                  "if the service is to be invoked via the "
                                  "web service client")
    
    def _setEnviron(self, environ):
        if not isinstance(environ, dict):
            raise TypeError("Expecting dict type for 'environ' property")
        self._environ = environ
        
    def _getEnviron(self):
        return self._environ
    
    environ = property(fget=_getEnviron, 
                       fset=_setEnviron, 
                       doc="WSGI environ dictionary")

    def _getLocalClient(self):
        """Get reference to WSGI service instance in environ"""
        raise NotImplementedError()
    
    localClient = property(fget=_getLocalClient, doc="local instance")
    
    def _localClientInEnviron(self):
        '''Check whether a reference is present in the WSGI environ to the 
        service to be queried.  Check also that if a URI was specified by the
        client, it matches the URI the local WSGI service is published under.
        
        This method is critical to the purpose of this class ie. enables
        clients to optimize calls to local services by avoiding calling them
        over the network and instead accessing them locally through the WSGI
        stack.
        
        The client class must have a uri attribute and the WSGI service 
        referenced must have a published URI attribute
        '''
        if self._environKeyName not in self._environ:
            log.debug("Checking for referenced WSGI service in environ: "
                      "the given key was not found in the environ dictionary")
            return False
        
        if self._wsClient:
            # A SOAP client was initialised - check to see if its URI matches
            # the URI for the service referenced in environ
            requestedURI = getattr(self._wsClient, 'uri', None)
            if requestedURI is None:
                log.debug("Checking for referenced WSGI service in environ: "
                          "No URI was set in the client request - assuming "
                          "call to local service")
                return True
            
            serviceURI = getattr(self._environ[self._environKeyName], 
                                 'publishedURI',
                                 None)
            if serviceURI is None:
                log.debug("Checking for referenced WSGI service in environ: "
                          "no service URI was set")
                return False
            else:
                log.debug("Checking for referenced WSGI service in environ: "
                          "testing requested URI equals the referenced WSGI "
                          "service's URI")
                return requestedURI == serviceURI
        else:
            log.debug("Checking for referenced WSGI service in environ: "
                      "no client is set - a local instance must be referenced")
            return True
    
    # Define as property for convenient call syntax
    localClientInEnviron = property(fget=_localClientInEnviron,
                                    doc="return True if referenced instance "
                                        "is available in WSGI environ")