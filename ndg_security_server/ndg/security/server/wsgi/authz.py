"""WSGI Policy Enforcement Point Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "16/01/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
__license__ = "BSD - see LICENSE file in top-level directory"
import logging
log = logging.getLogger(__name__)

import warnings
from time import time
from urlparse import urlunsplit
from httplib import UNAUTHORIZED, FORBIDDEN

from ndg.security.common.utils.classfactory import importClass
from ndg.security.common.X509 import X509Cert
from ndg.security.common.saml_utils.bindings import AttributeQuerySslSOAPBinding

from ndg.security.common.credentialwallet import (NDGCredentialWallet,
                                                  SAMLCredentialWallet)
from ndg.security.server.wsgi import (NDGSecurityMiddlewareBase, 
                                      NDGSecurityMiddlewareConfigError)

from ndg.security.server.wsgi import (NDGSecurityMiddlewareBase, 
                                      NDGSecurityMiddlewareConfigError)
from ndg.security.server.wsgi.authn import (SessionMiddlewareBase, 
                                            SessionHandlerMiddleware)

from ndg.security.common.authz.msi import (Policy, PIP, PIPBase, 
                                           PIPAttributeQuery, 
                                           PIPAttributeResponse, PDP, Request, 
                                           Response, Resource, Subject)


class PEPResultHandlerMiddleware(SessionMiddlewareBase):
    """This middleware is invoked if access is denied to a given resource.  It
    is incorporated into the call stack by passing it in to a MultiHandler 
    instance.  The MultiHandler is configured in the AuthorizationMiddlewareBase 
    class below.  The MultiHandler is passed a checker method which determines
    whether to allow access, or call this interface.   The checker is
    implemented in the AuthorizationHandler.  See below ...
    
    This class can be overridden to define custom behaviour for the access
    denied response e.g. include an interface to enable users to register for
    the dataset from which they have been denied access.  See 
    AuthorizationMiddlewareBase pepResultHandler keyword.
    
    SessionMiddlewareBase base class defines user session key and 
    isAuthenticated property
    """
    
    def __init__(self, app, global_conf, prefix='', **app_conf):
        '''
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
        super(PEPResultHandlerMiddleware, self).__init__(app,
                                                         global_conf,
                                                         prefix=prefix,
                                                         **app_conf)
               
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        
        log.debug("PEPResultHandlerMiddleware.__call__ ...")
        
        self.session = self.environ.get(self.sessionKey)
        if not self.isAuthenticated:
            # This check is included as a precaution: this condition should be
            # caught be the AuthNRedirectHandlerMiddleware or PEPFilter
            log.warning("PEPResultHandlerMiddleware: user is not "
                        "authenticated - setting HTTP 401 response")
            return self._setErrorResponse(code=UNAUTHORIZED)
        else:
            # Get response message from PDP recorded by PEP
            pepCtx = self.session.get('pepCtx', {})
            pdpResponse = pepCtx.get('response')
            msg = getattr(pdpResponse, 'message', '')
                
            response = ("Access is forbidden for this resource:%s"
                        "Please check with your site administrator that you "
                        "have the required access privileges." % 
                        msg.join(('\n\n',)*2))

            return self._setErrorResponse(code=FORBIDDEN, msg=response)


class PEPFilterError(Exception):
    """Base class for PEPFilter exception types"""
    
class PEPFilterConfigError(PEPFilterError):
    """Configuration related error for PEPFilter"""

class PEPFilter(SessionMiddlewareBase):
    """PEP (Policy Enforcement Point) WSGI Middleware.  The PEP enforces
    access control decisions made by the PDP (Policy Decision Point).  In 
    this case, it follows the WSG middleware filter pattern and is configured
    in a pipeline upstream of the application(s) which it protects.  if an 
    access denied decision is made, the PEP enforces this by returning a 
    403 Forbidden HTTP response without the application middleware executing
    
    SessionMiddlewareBase base class defines user session key and 
    isAuthenticated property
    """
    TRIGGER_HTTP_STATUS_CODE = str(FORBIDDEN)
    MIDDLEWARE_ID = 'PEPFilter'
    POLICY_PARAM_PREFIX = 'policy.'
    SESSION_KEYNAME = 'sessionKey'
    POLICY_FILEPATH_PARAMNAME = 'filePath'
    
    def __init__(self, app, global_conf, prefix='', **local_conf):
        """Initialise the PIP (Policy Information Point) and PDP (Policy 
        Decision Point).  The PDP makes access control decisions based on
        a given policy.  The PIP manages the retrieval of user credentials on 
        behalf of the PDP
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        
        """       
        # Initialise the PDP reading in the policy
        policyCfg = PEPFilter._filterKeywords(local_conf, 
                                              PEPFilter.POLICY_PARAM_PREFIX)
        self.policyFilePath = policyCfg[PEPFilter.POLICY_FILEPATH_PARAMNAME]
        policy = Policy.Parse(policyCfg[PEPFilter.POLICY_FILEPATH_PARAMNAME])
        
        # Initialise the Policy Information Point to None.  This object is
        # created and set later.  See AuthorizationMiddlewareBase.
        self.pdp = PDP(policy, None)
        
        self.sessionKey = local_conf.get(PEPFilter.SESSION_KEYNAME, 
                                         PEPFilter.propertyDefaults[
                                                    PEPFilter.SESSION_KEYNAME])
        
        super(PEPFilter, self).__init__(app,
                                        global_conf,
                                        prefix=prefix,
                                        **local_conf)

    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        session = environ.get(self.sessionKey)
        if session is None:
            raise PEPFilterConfigError('No beaker session key "%s" found in '
                                       'environ' % self.sessionKey)
            
        queryString = environ.get('QUERY_STRING', '')
        resourceURI = urlunsplit(('', '', self.pathInfo, queryString, ''))
        
        # Check for a secured resource
        matchingTargets = self._getMatchingTargets(resourceURI)
        targetMatch = len(matchingTargets) > 0
        if not targetMatch:
            log.debug("PEPFilter.__call__: granting access - no matching URI "
                      "path target was found in the policy for URI path [%s]", 
                      resourceURI)
            return self._app(environ, start_response)

        log.debug("PEPFilter.__call__: found matching target(s):\n\n %s\n"
                  "\nfrom policy file [%s] for URI Path=[%s]\n",
                  '\n'.join(["RegEx=%s" % t for t in matchingTargets]), 
                  self.policyFilePath,
                  resourceURI)
        
        if not self.isAuthenticated:
            log.info("PEPFilter.__call__: user is not authenticated - setting "
                     "HTTP 401 response ...")
            
            # Set a 401 response for an authentication handler to capture
            return self._setErrorResponse(code=UNAUTHORIZED)
        
        log.debug("PEPFilter.__call__: creating request to call PDP to check "
                  "user authorisation ...")
        
        # Make a request object to pass to the PDP
        request = Request()
        request.subject[Subject.USERID_NS] = session['username']
        
        # IdP Session Manager specific settings:
        #
        # The following won't be set if the IdP running the OpenID Provider
        # hasn't also deployed a Session Manager.  In this case, the
        # Attribute Authority will be queried directly from here without a
        # remote Session Manager intermediary to cache credentials
        request.subject[Subject.SESSIONID_NS] = session.get('sessionId')
        request.subject[Subject.SESSIONMANAGERURI_NS] = session.get(
                                                        'sessionManagerURI')
        request.resource[Resource.URI_NS] = resourceURI

        
        # Call the PDP
        response = self.pdp.evaluate(request)        
        
        # Record the result in the user's session to enable later 
        # interrogation by the AuthZResultHandlerMiddleware
        session['pepCtx'] = {'request': request, 'response': response,
                             'timestamp': time()}
        session.save()
        
        if response.status == Response.DECISION_PERMIT:
            log.info("PEPFilter.__call__: PDP granted access for URI path "
                     "[%s] using policy [%s]", 
                     resourceURI, 
                     self.policyFilePath)
            
            return self._app(environ, start_response)
        else:
            log.info("PEPFilter.__call__: PDP returned a status of [%s] "
                     "denying access for URI path [%s] using policy [%s]", 
                     response.decisionValue2String[response.status],
                     resourceURI,
                     self.policyFilePath) 
            
            # Trigger AuthZResultHandlerMiddleware by setting a response 
            # with HTTP status code equal to the TRIGGER_HTTP_STATUS_CODE class
            # attribute value
            triggerStatusCode = int(PEPFilter.TRIGGER_HTTP_STATUS_CODE)
            return self._setErrorResponse(code=triggerStatusCode)

    def _getMatchingTargets(self, resourceURI):
        """This method may only be called following __call__ as __call__
        updates the pathInfo property
        
        @type resourceURI: basestring
        @param resourceURI: the URI of the requested resource
        @rtype: list
        @return: return list of policy target objects matching the current 
        path 
        """
        matchingTargets = [target for target in self.pdp.policy.targets 
                           if target.regEx.match(resourceURI) is not None]
        return matchingTargets

    def multiHandlerInterceptFactory(self):
        """Return a checker function for use with AuthKit's MultiHandler.
        MultiHandler can be used to catch HTTP 403 Forbidden responses set by
        an application and call middleware (AuthZResultMiddleware) to handle
        the access denied message.
        """
        
        def multiHandlerIntercept(environ, status, headers):
            """AuthKit MultiHandler checker function to intercept 
            unauthorised response status codes from applications to be 
            protected.  This function's definition is embedded into a
            factory method so that this function has visibility to the 
            PEPFilter object's attributes if required.
            
            @type environ: dict
            @param environ: WSGI environment dictionary
            @type status: basestring
            @param status: HTTP response code set by application middleware
            that this intercept function is to protect
            @type headers: list
            @param headers: HTTP response header content"""
            
            if status.startswith(PEPFilter.TRIGGER_HTTP_STATUS_CODE):
                log.debug("PEPFilter: found [%s] status for URI path [%s]: "
                          "invoking access denied response",
                          PEPFilter.TRIGGER_HTTP_STATUS_CODE,
                          environ['PATH_INFO'])
                return True
            else:
                # No match - it's publicly accessible
                log.debug("PEPFilter: the return status [%s] for this URI "
                          "path [%s] didn't match the trigger status [%s]",
                          status,
                          environ['PATH_INFO'],
                          PEPFilter.TRIGGER_HTTP_STATUS_CODE)
                return False
        
        return multiHandlerIntercept
        
    @staticmethod
    def _filterKeywords(conf, prefix):
        filteredConf = {}
        prefixLen = len(prefix)
        for k, v in conf.items():
            if k.startswith(prefix):
                filteredConf[k[prefixLen:]] = conf.pop(k)
                
        return filteredConf

    def _getPDP(self):
        if self._pdp is None:
            raise TypeError("PDP object has not been initialised")
        return self._pdp
    
    def _setPDP(self, pdp):
        if not isinstance(pdp, (PDP, None.__class__)):
            raise TypeError("Expecting %s or None type for pdp; got %r" %
                            (PDP.__class__.__name__, pdp))
        self._pdp = pdp

    pdp = property(fget=_getPDP,
                   fset=_setPDP,
                   doc="Policy Decision Point object makes access control "
                       "decisions on behalf of the PEP")

   
class NdgPIPMiddlewareError(Exception):
    """Base class for Policy Information Point WSGI middleware exception types
    """
    
class NdgPIPMiddlewareConfigError(NdgPIPMiddlewareError):
    """Configuration related error for Policy Information Point WSGI middleware
    """    
    
class NdgPIPMiddleware(PIP, NDGSecurityMiddlewareBase):
    '''Extend Policy Information Point to enable caching of credentials in
    a NDGCredentialWallet object held in beaker.session
    '''
    ENVIRON_KEYNAME = 'ndg.security.server.wsgi.authz.NdgPIPMiddleware'
       
    propertyDefaults = {
        'sessionKey': 'beaker.session.ndg.security',
    }
    propertyDefaults.update(NDGSecurityMiddlewareBase.propertyDefaults)
  
    def __init__(self, app, global_conf, prefix='', **local_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        
        # Pre-process list items splitting as needed
        if isinstance(local_conf.get('caCertFilePathList'), basestring):
            local_conf[
                'caCertFilePathList'] = NDGSecurityMiddlewareBase.parseListItem(
                                            local_conf['caCertFilePathList'])
            
        if isinstance(local_conf.get('sslCACertFilePathList'), basestring):
            local_conf[
                'sslCACertFilePathList'
                ] = NDGSecurityMiddlewareBase.parseListItem(
                                        local_conf['sslCACertFilePathList'])
            
        PIP.__init__(self, prefix=prefix, **local_conf)
        
        for k in local_conf.keys():
            if k.startswith(prefix):
                del local_conf[k]
                
        NDGSecurityMiddlewareBase.__init__(self,
                                           app,
                                           global_conf,
                                           prefix=prefix,
                                           **local_conf)
        
    def __call__(self, environ, start_response):
        """Take a copy of the session object so that it is in scope for
        _getAttributeCertificate call and add this instance to the environ
        so that the PEPFilter can retrieve it and pass on to the PDP
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        self.session = environ.get(self.sessionKey)
        if self.session is None:
            raise NdgPIPMiddlewareConfigError('No beaker session key "%s" found '
                                           'in environ' % self.sessionKey)
        environ[NdgPIPMiddleware.ENVIRON_KEYNAME] = self
        
        return self._app(environ, start_response)
               
    def _getAttributeCertificate(self, attributeAuthorityURI, **kw):
        '''Extend base class implementation to make use of the 
        NDGCredentialWallet Attribute Certificate cache held in the beaker 
        session.  If no suitable certificate is present invoke default behaviour 
        and retrieve an Attribute Certificate from the Attribute Authority or 
        Session Manager specified

        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @type username: basestring
        @param username: subject user identifier - could be an OpenID        
        @type sessionId: basestring
        @param sessionId: Session Manager session handle
        @type sessionManagerURI: basestring
        @param sessionManagerURI: URI to remote session manager service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''
        # Check for a wallet in the current session - if not present, create
        # one.  See ndg.security.server.wsgi.authn.SessionHandlerMiddleware
        # for session keys.  The 'credentialWallet' key is deleted along with
        # any other security keys when the user logs out
        if not 'credentialWallet' in self.session:
            log.debug("NdgPIPMiddleware._getAttributeCertificate: adding a "
                      "Credential Wallet to user session [%s] ...",
                      self.session['username'])
            
            self.session['credentialWallet'] = NDGCredentialWallet(
                                            userId=self.session['username'])
            self.session.save()
            
        # Take reference to wallet for efficiency
        credentialWallet = self.session['credentialWallet']    
        
        # Check for existing credentials cached in wallet            
        credentialItem = credentialWallet.credentialsKeyedByURI.get(
                                                        attributeAuthorityURI)        
        if credentialItem is not None:
            log.debug("NdgPIPMiddleware._getAttributeCertificate: retrieved "
                      "existing Attribute Certificate cached in Credential "
                      "Wallet for user session [%s]",
                      self.session['username'])

            # Existing cached credential found - skip call to remote Session
            # Manager / Attribute Authority and return this certificate instead
            return credentialItem.credential
        else:   
            attrCert = PIP._getAttributeCertificate(self,
                                                    attributeAuthorityURI,
                                                    **kw)
            
            log.debug("NdgPIPMiddleware._getAttributeCertificate: updating "
                      "Credential Wallet with retrieved Attribute "
                      "Certificate for user session [%s]",
                      self.session['username'])
        
            # Update the wallet with this Attribute Certificate so that it's 
            # cached for future calls
            credentialWallet.addCredential(attrCert,
                                attributeAuthorityURI=attributeAuthorityURI)
            
            return attrCert

   
class SamlPIPMiddlewareError(Exception):
    """Base class for SAML based Policy Information Point WSGI middleware 
    exception types
    """

  
class SamlPIPMiddlewareConfigError(NdgPIPMiddlewareError):
    """Configuration related error for Policy Information Point WSGI middleware
    """
    

class SamlPIPMiddleware(PIPBase, NDGSecurityMiddlewareBase):
    '''Extend Policy Information Point to enable caching of SAML credentials in
    a SAMLCredentialWallet object held in beaker.session
    '''
    ENVIRON_KEYNAME = 'ndg.security.server.wsgi.authz.SamlPIPMiddleware'
       
    propertyDefaults = {
        'sessionKey': 'beaker.session.ndg.security',
    }
    propertyDefaults.update(NDGSecurityMiddlewareBase.propertyDefaults)
  
    CREDENTIAL_WALLET_SESSION_KEYNAME = \
        SessionHandlerMiddleware.CREDENTIAL_WALLET_SESSION_KEYNAME
    USERNAME_SESSION_KEYNAME = \
        SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME
         
    ATTRIBUTE_QUERY_ATTRNAME = 'attributeQuery'
    LEN_ATTRIBUTE_QUERY_ATTRNAME = len(ATTRIBUTE_QUERY_ATTRNAME)
          
    def __init__(self, app, global_conf, prefix='', **local_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        self.session = None
        self.__attributeQueryBinding = AttributeQuerySslSOAPBinding()
        
        nameOffset = len(prefix)
        for k in local_conf.keys():
            if k.startswith(prefix):
                val = local_conf.pop(k)
                name = k[nameOffset:]
                setattr(self, name, val)
                
        if not self.__attributeQueryBinding.issuerName:
            issuerX509Cert = X509Cert.Read(
                    self.__attributeQueryBinding.sslCtxProxy.sslCertFilePath)
            self.__attributeQueryBinding.issuerName = str(issuerX509Cert.dn)
                
        NDGSecurityMiddlewareBase.__init__(self, app, {})
            
    def __setattr__(self, name, value):
        """Enable setting of AttributeQuerySslSOAPBinding attributes from
        names starting with attributeQuery.* / attributeQuery_*.  Addition for
        setting these values from ini file
        """

        # Coerce into setting AttributeQuerySslSOAPBinding attributes - 
        # names must start with 'attributeQuery\W' e.g.
        # attributeQuery.clockSkew or attributeQuery_issuerDN
        if name.startswith(SamlPIPMiddleware.ATTRIBUTE_QUERY_ATTRNAME):
            setattr(self.__attributeQueryBinding, 
                    name[SamlPIPMiddleware.LEN_ATTRIBUTE_QUERY_ATTRNAME+1:], 
                    value)
        else:
            super(SamlPIPMiddleware, self).__setattr__(name, value)    

    @property
    def attributeQueryBinding(self):
        """SAML SOAP Attribute Query client binding object"""
        return self.__attributeQueryBinding
                
    def __call__(self, environ, start_response):
        """Take a copy of the session object so that it is in scope for
        attributeQuery call and add this instance to the environ
        so that the PEPFilter can retrieve it and pass on to the PDP
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        self.session = environ.get(self.sessionKey)
        if self.session is None:
            raise SamlPIPMiddlewareConfigError('No beaker session key "%s" '
                                               'found in environ' % 
                                               self.sessionKey)
        environ[SamlPIPMiddleware.ENVIRON_KEYNAME] = self
        
        return self._app(environ, start_response)
    
    def attributeQuery(self, attributeQuery):
        """Query the Attribute Authority specified in the request to retrieve
        the attributes if any corresponding to the subject
        
        @type attributeResponse: PIPAttributeQuery
        @param attributeResponse: 
        @rtype: PIPAttributeResponse
        @return: response containing the attributes retrieved from the
        Attribute Authority"""
        if not isinstance(attributeQuery, PIPAttributeQuery):
            raise TypeError('Expecting %r type for input "attributeQuery"; '
                            'got %r' % (AttributeQuery, type(attributeQuery)))
                            
        attributeAuthorityURI = attributeQuery[
                                        PIPAttributeQuery.ATTRIBUTEAUTHORITY_NS]
        
        log.debug("SamlPIPMiddleware: received attribute query: %r", 
                  attributeQuery)
               
        # Check for a wallet in the current session - if not present, create
        # one.  See ndg.security.server.wsgi.authn.SessionHandlerMiddleware
        # for session keys.  The 'credentialWallet' key is deleted along with
        # any other security keys when the user logs out
        credentialWalletKeyName = \
                            SamlPIPMiddleware.CREDENTIAL_WALLET_SESSION_KEYNAME
        usernameKeyName = SamlPIPMiddleware.USERNAME_SESSION_KEYNAME
            
        if not credentialWalletKeyName in self.session:
            log.debug("SamlPIPMiddleware.attributeQuery: adding a "
                      "Credential Wallet to user session [%s] ...",
                      self.session[usernameKeyName])
            
            credentialWallet = SAMLCredentialWallet()
            credentialWallet.userId = self.session[usernameKeyName]
            
            self.session[credentialWalletKeyName] = credentialWallet
            self.session.save()
        else:    
            # Take reference to wallet for efficiency
            credentialWallet = self.session[credentialWalletKeyName]    
        
        # Check for existing credentials cached in wallet            
        credentialItem = credentialWallet.credentialsKeyedByURI.get(
                                                    attributeAuthorityURI)
        if credentialItem is None:
            # No assertion is cached - make a fresh SAML Attribute Query
            self.attributeQueryBinding.subjectID = credentialWallet.userId
            response = self.attributeQueryBinding.send(
                                                    uri=attributeAuthorityURI)
            for assertion in response.assertions:
                credentialWallet.addCredential(assertion)
            
            log.debug("SamlPIPMiddleware.attributeQuery: updating Credential "
                      "Wallet with retrieved SAML Attribute Assertion "
                      "for user session [%s]", self.session[usernameKeyName])
        else:
            log.debug("SamlPIPMiddleware.attributeQuery: retrieved existing "
                      "SAML Attribute Assertion cached in Credential Wallet "
                      "for user session [%s]", self.session[usernameKeyName])

        attributeResponse = PIPAttributeResponse()
        attributeResponse[Subject.ROLES_NS] = []
        
        # Unpack assertion attribute values and add to the response object
        for credentialItem in credentialWallet.credentials.values():
            for statement in credentialItem.credential.attributeStatements:
                for attribute in statement.attributes:
                    attributeResponse[Subject.ROLES_NS] += [
                        attributeValue.value 
                        for attributeValue in attribute.attributeValues
                        if attributeValue.value not in attributeResponse[
                                                            Subject.ROLES_NS]
                    ]
        
        log.debug("SamlPIPMiddleware.attributeQuery response: %r", 
                  attributeResponse)
        
        return attributeResponse
    
           
from authkit.authenticate.multi import MultiHandler

class AuthorizationMiddlewareError(Exception):
    """Base class for AuthorizationMiddlewareBase exceptions"""
    
class AuthorizationMiddlewareConfigError(Exception):
    """AuthorizationMiddlewareBase configuration related exceptions"""
 
   
class AuthorizationMiddlewareBase(NDGSecurityMiddlewareBase):
    '''Virtual class - A base Handler to call Policy Enforcement Point 
    middleware to intercept requests and enforce access control decisions.  
    
    Extend THIS class adding the new type to any WSGI middleware chain ahead of 
    the application(s) which it is to protect.  To make an implementation for 
    this virtual class, set PIP_MIDDLEWARE_CLASS in the derived type to a 
    valid Policy Information Point Class.  Use in conjunction with 
    ndg.security.server.wsgi.authn.AuthenticationMiddleware
    '''
    PEP_PARAM_PREFIX = 'pep.filter.'
    PIP_PARAM_PREFIX = 'pip.'
    PEP_RESULT_HANDLER_PARAMNAME = "pepResultHandler"
    
        
    class PIP_MIDDLEWARE_CLASS(object):
        """Policy Information Point WSGI middleware abstract base, 
        implementations should retrieve user credentials to enable the PDP to 
        make access control decisions
        """
        def __init__(self, app, global_conf, prefix='', **local_conf):  
            raise NotImplementedError(' '.join(
                AuthorizationMiddlewareBase.PIP_MIDDLEWARE_CLASS.__doc__.split())
            )
    
    def __init__(self, app, global_conf, prefix='', **app_conf):
        """Set-up Policy Enforcement Point to enforce access control decisions
        based on the URI path requested and/or the HTTP response code set by
        application(s) to be protected.  An AuthKit MultiHandler is setup to 
        handle the latter.  PEPResultHandlerMiddleware handles the output
        set following an access denied decision
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
        authzPrefix = prefix + AuthorizationMiddlewareBase.PEP_PARAM_PREFIX
        pepFilter = PEPFilter(app,
                              global_conf,
                              prefix=authzPrefix,
                              **app_conf)
        pepInterceptFunc = pepFilter.multiHandlerInterceptFactory()
        
        # Slot in the Policy Information Point in the WSGI stack at this point
        # so that it can take a copy of the beaker session object from environ
        # ahead of the PDP's request to it for an Attribute Certificate
        pipPrefix = AuthorizationMiddlewareBase.PIP_PARAM_PREFIX
        pipFilter = self.__class__.PIP_MIDDLEWARE_CLASS(pepFilter,
                                                        global_conf,
                                                        prefix=pipPrefix,
                                                        **app_conf)
        pepFilter.pdp.pip = pipFilter
        
        app = MultiHandler(pipFilter)

        pepResultHandlerClassName = app_conf.pop(
                prefix+AuthorizationMiddlewareBase.PEP_RESULT_HANDLER_PARAMNAME, 
                None)
        if pepResultHandlerClassName is None:
            pepResultHandler = PEPResultHandlerMiddleware
        else:
            pepResultHandler = importClass(pepResultHandlerClassName,
                                        objectType=PEPResultHandlerMiddleware)
            
        app.add_method(PEPFilter.MIDDLEWARE_ID,
                       pepResultHandler.filter_app_factory,
                       global_conf,
                       prefix=prefix,
                       **app_conf)
        
        app.add_checker(PEPFilter.MIDDLEWARE_ID, pepInterceptFunc)                
        
        super(AuthorizationMiddlewareBase, self).__init__(app,
                                                      global_conf,
                                                      prefix=prefix,
                                                      **app_conf)
 

class NDGAuthorizationMiddleware(AuthorizationMiddlewareBase):
    """Implementation of AuthorizationMiddlewareBase using the NDG Policy
    Information Point interface.  This retrieves attributes over the SOAP/WSDL
    Attribute Authority interface 
    (ndg.security.server.wsgi.attributeauthority.AttributeAuthoritySOAPBindingMiddleware)
    and caches NDG Attribute Certificates in an 
    ndg.security.common.credentialWallet.NDGCredentialWallet
    """      
    PIP_MIDDLEWARE_CLASS = NdgPIPMiddleware   


class AuthorizationMiddleware(NDGAuthorizationMiddleware):
    """Include this class for backwards compatibility - see warning message
    in FUTURE_DEPRECATION_WARNING_MSG class variable"""
    FUTURE_DEPRECATION_WARNING_MSG = (
        "AuthorizationMiddleware will be deprecated in future releases.  "
        "NDGAuthorizationMiddleware is a drop in replacement but should be "
        "replaced with SAMLAuthorizationMiddleware instead")
    
    def __init__(self, *arg, **kw):
        warnings.warn(AuthorizationMiddleware.FUTURE_DEPRECATION_WARNING_MSG,
                      PendingDeprecationWarning)
        log.warning(AuthorizationMiddleware.FUTURE_DEPRECATION_WARNING_MSG) 
        super(AuthorizationMiddleware, self).__init__(*arg, **kw)


class SAMLAuthorizationMiddleware(AuthorizationMiddlewareBase):
    """Implementation of AuthorizationMiddlewareBase using the SAML Policy
    Information Point interface.  This retrieves attributes over the SOAP/SAML
    Attribute Authority interface 
    (ndg.security.server.wsgi.saml.SOAPAttributeInterfaceMiddleware) and caches 
    SAML Assertions in a 
    ndg.security.common.credentialWallet.SAMLCredentialWallet
    """      
    PIP_MIDDLEWARE_CLASS = SamlPIPMiddleware
    