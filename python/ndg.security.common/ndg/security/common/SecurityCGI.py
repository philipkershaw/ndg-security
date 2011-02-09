#!/usr/bin/env python
"""NDG Security CGI Interface between Service Providers and Identiy Providers

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/05/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

from Cookie import SimpleCookie

import sys
import cgi
import os
import base64

# Set cookie expiry
from datetime import datetime
from datetime import timedelta

from NDG.SecurityClient import *
from NDG.Session import UserSession
from NDG.Session import UserSessionError


class SecurityCGIError(Exception):
    """Exception handling for NDG Security CGI class."""
    pass


# Default style for HTML pages.  This can easily be overriden using keyword
# settings or overriding methods in a derived class.
_defStyle = """<style type=\"text/css\">
    <!--
    .al {
    text-align: justify
    }
    a{
    text-decoration:none;
    }
    a:hover{
    color:#0000FF;
    }
        body { font-family: Verdana, sans-serif; font-size: 11}
        table { font-family: Verdana, sans-serif; font-size: 11}
    -->
</style>"""


# Nb. Multiple inheritance but should be safe because FieldStorage doesn't
# inherit from anything.  Inheriting from object allows the use of 
# property() and super()
class _SecurityCGI(object, cgi.FieldStorage):
    """CGI Service Provider - Identity Provider interface base class for NDG 
    Security
    
    Service Provider (SP)    - serves NDG resources over http/https
    Identity Provider (IdP)  - holds NDG user accounts and supports 
                               authentication over https
    """

    # Field used in forms/URI args to tell the Identity Provider the 
    # Service Provider URI to return credentials to.  It must use HTTPS
    # unless returnURI and IdP URI are in the same domain.
    returnURItag = "returnURI"
    
    # Attribute Certificate request options
    acAllowMapping = "allowMapping"
    acAllowMappingWithPrompt = "allowMappingWithPrompt"
    acNoMapping = "noMapping"
    
    acMappingFlags = [acAllowMapping, acAllowMappingWithPrompt, acNoMapping]

    # Check returnURI uses HTTPS
    _httpsSpecifier = "https:"
    _httpSpecifier = "http:"    
    
    
    #_________________________________________________________________________
    def __init__(self,
                 scriptName,
                 clntCertFilePath=None,
                 clntPriKeyFilePath=None,
                 clntPriKeyPwd=None,
                 wsDebug=False,
                 **cgiFieldStorageKwArgs):
        """scriptName:            Name of IdP script specified as the action
                                  for HTML forms
        clntCertFilePath:    file path to client public key.  The CGI
                                  script must have access to a public/private
                                  key to enable encryption of return traffic
                                  from NDG security WSs.  IF THIS KEYWORD IS
                                  NOT SET, RETURN TRAFFIC IS NOT ENCRYPTED.
        clntPriKeyFilePath:       file path to client private key.
        clntPriKeyPwd:            password protecting the private key.  If no 
                                  password is set, omit this keyword.
        wsDebug:                  print output from WS transactions to stderr
                                  for debu purposes.
        """
        
        self.clntCertFilePath = clntCertFilePath
        self.clntPriKeyFilePath = clntPriKeyFilePath
        self.clntPriKeyPwd = clntPriKeyPwd

        self.scriptName = scriptName

        self._wsDebug = False        
        self.acMappingFlag = self.acAllowMappingWithPrompt
        self.attCert = None
                
        # Read fields so that self becomes a dictionary of the fields
        cgi.FieldStorage.__init__(self, **cgiFieldStorageKwArgs)

 
    #_________________________________________________________________________
    def processFields(self, **kwargs):
        """Call appropriate actions according to the fields set"""        
        raise NotImplementedError, \
            self.processFields.__doc__.replace('\n       ','')
    
    
    #_________________________________________________________________________
    # Could have used __call__ = processFields here but then derived classes
    # using __call__ would pick up _SecurityCGI.processFields instead of any
    # overridden version they implemented
    def __call__(self, **kwargs):
        """Alias to processFields method"""
        self.processFields(**kwargs)


    #_________________________________________________________________________
    def __getACmappingFlag(self):
        """Flag determines whether mapping is permitted when contacting an
        Attribute Authority to get an Attribute Certificate"""
        return self.__acMappingFlag


    def __setACmappingFlag(self, acMappingFlag):
        """Flag determines whether mapping is permitted when contacting an
        Attribute Authority to get an Attribute Certificate"""
        
        if acMappingFlag not in self.acMappingFlags:
            raise AttributeError, \
                "\"%s\" is invalid for acMappingFlag" % acMappingFlag
                
        self.__acMappingFlag = acMappingFlag
 
        
    def __delACmappingFlag(self):
        """Prevent certificate mapping flag from being deleted."""
        raise AttributeError, \
                        "\"acMappingFlag\" attribute cannot be deleted"
       
    
    acMappingFlag = property(fget=__getACmappingFlag,
                            fset=__setACmappingFlag,
                            fdel=__delACmappingFlag,
                            doc="mapping flag for AttCert requests to an AA")
    
    
    #_________________________________________________________________________
    def _getAttCert(self, sessCookie=None, reqRole=None):
        """Contact Attribute Authority to get Attribute Certificate for data
        access

        sessCookie:     NDG security session cookie
        reqRole:        specify the required role to get authorisation.  Set
                        this to optimise the process for getting the required
                        AC from a trusted host in order to perform mapping"""

        # Check for session cookie input
        if not sessCookie:
            # No cookie set as input argument check for environment variable
            if 'HTTP_COOKIE' in os.environ:
                sessCookie = SimpleCookie(os.environ['HTTP_COOKIE'])    
            else:
                raise SecurityCGIError, \
                    "Attribute certificate request requires a security cookie"

        # Check cookie is valid
        try:
            UserSession.isValidSecurityCookie(sessCookie, raiseExcep=True)
            
        except UserSessionError, e:
            raise SecurityCGIError, 'Checking existing session cookie: %s' % e


        # Configure flags for attribute certificate request.  This determines
        # whether mapping of certificates from trusted hosts is allowed
        if self.acMappingFlag == self.acAllowMapping:
            bMapFromTrustedHosts = True
            bRtnExtAttCertList = False

        elif self.acMappingFlag == self.acAllowMappingWithPrompt:
            bMapFromTrustedHosts = False
            bRtnExtAttCertList = True
        else:
            bMapFromTrustedHosts = False
            bRtnExtAttCertList = False


        # Instantiate WS proxy and request authorisation
        try:
            if not self._smClnt:
                self._smClnt = SessionClient(\
                            smWSDLuri=self.smWSDLuri,
                            smCertFilePath=self.smCertFilePath,
                            clntCertFilePath=self.clntCertFilePath,
                            clntPriKeyFilePath=self.clntPriKeyFilePath,
                            traceFile=self._wsDebug and sys.stderr or None)

            authzResp = self._smClnt.reqAuthorisation(sessCookie=sessCookie,
                                    aaWSDLuri=self.aaWSDLuri,
                                    aaCert=self.aaCert,
                                    reqRole=reqRole,
                                    mapFromTrustedHosts=bMapFromTrustedHosts,
                                    rtnExtAttCertList=bRtnExtAttCertList,
                                    clntPriKeyPwd=self.clntPriKeyPwd)
        except Exception, e:
            raise SecurityCGIError, "Attribute Certificate request: %s" % e


        if authzResp['statCode'] == authzResp.AccessGranted:
            self.onAttCertGranted(authzResp['attCert'])
        
        elif authzResp['statCode'] == authzResp.AccessDenied:
            self.onAttCertDenied(authzResp['extAttCertList'], 
                                 authzResp['errMsg'])
            
        elif authzResp['statCode'] == authzResp.AccessError:
            raise SecurityCGIError, authzResp['errMsg']
            
    
    #_________________________________________________________________________
    def onAttCertGranted(self, attCert):
        """Callback invoked by getAttCert - handle case where an Attribute
        Authority has granted a new attribute certificate to the user.  Derive
        from this class and override this method as required.
        """
        pass
    
    
    #_________________________________________________________________________
    def onAttCertDenied(self, extAttCertList, errMsg):
        """Callback invoked by getAttCert - handle case where an Attribute
        Authority has denied an attribute certificate to the user.  Derive
        from this class and override this method as required.
        
        extAttCertList:    a list of attribute certificates from trusted
                           hosts.  Any of these could be selected and 
                           presented back to the target AA in order to get
                           a mapped certificate.  This list may be None if 
                           no ACs could be obtained or if the 
                           mapFromTrustedHosts flag in the call to the Session
                           Manager WS reqAuthorisation method was set to 
                           False.
                           
        errMsg:            the error message returned from the call to the
                           AA to get an AC."""
        
        if not extAttCertList:
            self.showLogin(pageTitle="Access denied by Attribute Authority")
            raise SecurityCGIError, errMsg
        
        else:
            # Display list of attCerts to choose from
            print \
"""Content-type: text/html

<html>
<head>
    <title>Select an Attribute Certificate</title>
    <style type=\"text/css\">
    <!--
    .al {
    text-align: justify
    }
    a{
    text-decoration:none;
    }
    a:hover{
    color:#0000FF;
    }
        body { font-family: Verdana, sans-serif; font-size: 11}
        table { font-family: Verdana, sans-serif; font-size: 11}
    -->
    </style>
</head>
<body>
    <form action="%s" method="POST">
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>"""
    
            for attCert in extAttCertList:
                print \
"""    <tr>
        <td>%s</td>
    </tr>""" % attCert['issuer']
                
                print \
"""    </tbody>
    </table>
    </form>
</body>
</html>"""
    
        # end of onAttCertDenied()
        

#_____________________________________________________________________________
class ServiceProviderSecurityCGI(_SecurityCGI):
    """CGI interface for a Service Provider requesting user credentials
    
    It enables the user to select an Identity Provider login page from a list 
    of trusted hosts, re-directs the user browser to the login and then can
    process credentials passed back from the IdP to enable a new NDG security
    cookie to be set in the Service Provider target domain.
    """
    
    # Field name used in forms and URI args to specify the URI for the
    # Identity Provider to redirect to following submit action in
    # showIdPsiteSelect method
    requestURItag = 'requestURI'
    
    #_________________________________________________________________________
    def __init__(self,
                 scriptName,
                 returnURI,
                 aaWSDLuri,
                 aaCertFilePath=None,
                 smWSDLuri=None,
                 smCertFilePath=None,
                 trustedIdPs=None,
                 cookieLifetimeHrs=8,
                 **securityCGIKwArgs):
        """scriptName:        Name of the script that uses this code.  It's
                              needed as the action of the HTML form for
                              showIdPsiteSelect to ensure that it can call
                              _requestCreds()
        returnURI:            Specifies the URI that the IdP selected by the
                              user should redirect back to once the user's
                              credentials have been obtained.  - Used by
                              _requestCreds.
        aaWSDLuri:            URI for Attribute Authority WSDL used to get a
                              list of login URI for trusted hosts
        smWSDLuri:            URI For Session Manager WSDL used for querying
                              user session wallet for Attribute Certificates.
                              Only needed for _getAttCert calls
        aaCertFilePath:     file path to Attribute Authority public key.
                              If not set, the client will make a WS call for
                              it.
        smCertFilePath:     file path to Session Manager public key.
                              If not set, the client will make a WS call for
                              it.  See information for smWSDLuri above.
        trustedIdPs:          dictionary of URIs for trusted hosts indexed by
                              hostname
        cookieLifetimeHrs:    cookie lifetime in hours for new cookie set in
                              Service Provider target domain.
        wsDebug:              print output from WS transactions to stderr"""

        self.returnURI = returnURI
        
        self.aaWSDLuri = aaWSDLuri
        self._aaClnt = None
        
        self.aaCertFilePath = aaCertFilePath

        self.smWSDLuri = smWSDLuri
        self._smClnt = None
        
        self.smCertFilePath = smCertFilePath


        self.trustedIdPs = trustedIdPs
        self.cookieLifetimeHrs = cookieLifetimeHrs

        # Work out expiry time offset from the time this script is run
        self.dtCookieExpiry = datetime.utcnow() + \
                            timedelta(seconds=self.cookieLifetimeHrs*60*60)

        self._wsDebug = False        
                
        super(ServiceProviderSecurityCGI, self).__init__(scriptName,
                                                         **securityCGIKwArgs)

 
    #_________________________________________________________________________
    def processFields(self, **kwargs):
        """Call appropriate actions according to the fields set"""

        # Check for security tags returned from Identity Provider URI
        credTagsSet = lambda tags: \
            not [True for tag in UserSession.cookieTags if tag not in tags]
         
        # Check for existing security cookie   
        credsPresent = lambda environ: 'HTTP_COOKIE' in environ and \
            UserSession.isValidSecurityCookie(environ['HTTP_COOKIE']) 
             
 
        if self.requestURItag in self:
            # Request credentials from user's identity provider
            self._requestCreds(**kwargs)

        elif credTagsSet(self):
            # Credentials tags were set -  set a new cookie at service 
            # provider site
            self._receiveCredsResponse(**kwargs)

        elif credsPresent(os.environ):
            self.onCredsSet(**kwargs)
            
        else:
            # Default to list of sites for user to select for login
            self.showIdPsiteSelect(**kwargs)

    
    #_________________________________________________________________________
    def showIdPsiteSelect(self,
                      trustedIdPs=None,
                      scriptName=None,
                      contentTypeHdr=True,
                      htmlTag=True,
                      hdrTag=True,
                      hdrTxt=_defStyle,
                      bodyTag=True,
                      bodyTxt="<h2>Security Credentials are Required</h2>",
                      pageTitle="Select your home site ..."):
        """Display a list of Identity Provider sites for the user to select
        to retrieve their credentials.  The user must have an account with one
        of these sites in order to be able to proceed
        
        Override this method as required for custom IdP page presentation.
        However, the following field must be set:
        
        ServiceProviderSecurityCGI.requestURItag 
        
        This is the URI of the IdP login the user selected"""
        
        if trustedIdPs:
            if not isinstance(trustedIdPs, dict):
                raise SecurityCGIError, \
                            "Expecting a dictionary type for \"trustedIdPs\""
                            
            self.trustedIdPs = trustedIdPs


        if not self.trustedIdPs:
            self.getTrustedIdPs()
            
        if scriptName:
            self.scriptName = scriptName
            
                
        if contentTypeHdr:
            print "Content-type: text/html\n\n"
                
        if htmlTag:
            print "<html>"

        if hdrTag:            
            print """<head>
            
    <title>%s</title>
    %s
</head>""" % (pageTitle, hdrTxt)
    
    
        if bodyTag:
            print "<body>"
        
        if bodyTxt:
            print bodyTxt
            
        # Form containing droplist for the trusted hosts
        print """    <form action="%s" method="POST">
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr>
      <td>
        <select name="%s">        
          <option value="">Select your home site...""" % \
                                      (self.scriptName, self.requestURItag)
          
        for IdPname, info in self.trustedIdPs.items():
            print "          <option value=\"%s\">%s" % \
                                                (info['loginURI'], IdPname)
                
        print \
"""        </select>
      </td>
      <td align="right">
        <input type=submit value="Go">
      </td>
    </tr>
    </tbody>
    </table>
    </form>"""

        if bodyTag:
            print "</body>"

        if htmlTag:
            print "</html>"
    
        # end of showIdPsiteSelect()


    #_________________________________________________________________________
    def onCredsSet(self, 
                   sessCookie=None,
                   pageTitle='Credentials Set',
                   hdrTxt=_defStyle,
                   bodyTxt='<h2>NDG Security session cookie set</h2>'):
        """This method is called when either:
        
        a) a user security cookie is already present in the Service 
        Provider URI's environment.
        
        or 
        
        b) a new cookie has been created from credentials returned from an
        Identity Provider.
        
        For b) this method should set the cookie in HTML sent to user's 
        browser.
        
        This method can be overridden by a derived class.  From this point
        on, the user is authenticated and a connection has been established to
        their session manager so the authorisation steps to set up access to
        a secured resource can now proceed.  Code in this method can initiate 
        these next steps.
        
        Nb. If SP and IdP are in the same domain sessCookie will not be
        set when the user authenticates because the cookie set at the 
        IdP login URI will be visible from the SP return URI as well.
        
        sessCookie:    NDG Security Cookie passed as a SimpleCookie type.  If
                       set, this method should set it in HTML output so that
                       it is transfered to the user's browser.
        pageTitle:     set a page title for the page output.
        hdTxt:         set HTML within <head>...</head>
        bodyTxt:       set HTML within <body>...</body>
        
        pageTitle, hdrTxt and BodyTxt can be ignored completely in a method of
        a derived class if required."""
        
        print """Content-type: text/html
%s

<html>
<head>
<title>%s</title>
%s
</head>
<body>
    %s
</body>
</html>""" % (sessCookie and sessCookie.output() or '', 
              pageTitle, 
              hdrTxt, 
              bodyTxt)


    #_________________________________________________________________________
    def getTrustedIdPs(self):
        """Call Attribute Authority to find out IdPs that this SP trusts.  
        i.e. the SP's Attribute Authority includes them in it's map
        configuration.  These can be use to populate list for a user to select 
        their Identity Provider for login"""
        
        try:
            if not self._aaClnt:
                self._aaClnt = AttAuthorityClient(aaWSDL=self.aaWSDLuri,
                            aaCertFilePath=self.aaCertFilePath,
                            clntCertFilePath=self.clntCertFilePath,
                            clntPriKeyFilePath=self.clntPriKeyFilePath,
                            traceFile=self._wsDebug and sys.stderr or None)

            # Include *this* host as a trusted Identity Provider
            self.trustedIdPs = self._aaClnt.getHostInfo(\
                                           clntPriKeyPwd=self.clntPriKeyPwd)
            
            # Retrieve other info for other trusted hosts
            self.trustedIdPs.update(self._aaClnt.getTrustedHostInfo(\
                                           clntPriKeyPwd=self.clntPriKeyPwd))
        except Exception, e:
            raise SecurityCGIError, "Getting list of trusted IdPs: %s" % e

    
    #_________________________________________________________________________
    def _createCookie(self, encodedExpiry=None):
        """Convert credentials passed over URI from users Identity Provider 
        into a new cookie"""

        if encodedExpiry:
            # Expiry is taken from encoded value passed over URI
            dtExpiry = None
            expiryStr = base64.urlsafe_b64decode(encodedExpiry)
        else:
            # Expiry is set from life time in hours input in __init__
            dtExpiry = self.dtCookieExpiry
            expiryStr = None

        
        try:
            tagsDict = dict([(tag, self[tag].value) \
                             for tag in UserSession.cookieTags])
        except KeyError, e:
            raise SecurityCGIError, "Missing cookie tag: %s" % e
        
        sessCookie =  UserSession.createSecurityCookie(dtExpiry=dtExpiry,
                                                       expiryStr=expiryStr,
                                                       **tagsDict)
        
        return sessCookie
    

    #_________________________________________________________________________
    def _requestCreds(self,
                      requestURI=None,
                      pageTitle='',
                      headTags='',
                      delayTime=0,
                      redirectMsg=''):
        """Request credentials from a user's Identity Provider
        
        requestURI:   site to request credentials from - default is 
                      self.requestURItag CGI form value
        pageTitle:    Give the redirect page a title
        headTags:     Optionally add additional tags in <head/> section
        delayTime:    time in seconds before carrying out redirect - redirect
                      page will be displayed in this interval
        redirectMsg:  Message to put on redirect page.  Can be plain text or
                      formatted HTML"""

        if requestURI is None:
            try:
                requestURI = self[self.requestURItag].value
                    
            except KeyError, e:
                raise SecurityCGIError, "Requesting credentials from an " + \
                                   "Identity provider: %s key is not set" % e
    
        print """Content-type: text/html

<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH" content="%d; url=%s?%s=%s">
%s
</head>
<body>
%s
</body>
</html>""" % (pageTitle, 
              delayTime, 
              requestURI, 
              self.returnURItag, 
              self.returnURI, 
              headTags, 
              redirectMsg)


    #_________________________________________________________________________
    def _receiveCredsResponse(self, encodedExpiry=None, **kwargs):
        """Service Provider site receives returned credentials and creates a 
        new cookie for its domain"""
        
        if not encodedExpiry and 'expires' in self:
            encodedExpiry = self['expires'].value

        sessCookie = self._createCookie(encodedExpiry=encodedExpiry)
        self.onCredsSet(sessCookie=sessCookie, **kwargs)
        

#_____________________________________________________________________________
class IdentityProviderSecurityCGI(_SecurityCGI):
    """CGI for an NDG Identity provider.  The IdP serves user credentials
    back to a requesting Service Provider.
    
    An NDG Service Provider redirects the user's browser to an IdP login
    script using this class.  If the user is already logged in, then a 
    security cookie will be present and it's content returned to the SP by
    http redirect.  If no cookie is present the user must login first but then
    similarly, the content of the new cookie is returned to the SP.  The SP
    can them set a new security cookie it's target domain."""
    
    # Form field name/URI keyword set by showLogin form in order to call
    # _authenticate()
    authenticateTag = "authenticate"
    
    
    #_________________________________________________________________________
    def __init__(self,
                 scriptName, 
                 smWSDLuri,
                 smCertFilePath=None,
                 userName=None,
                 passPhrase=None,
                 **securityCGIKwArgs):
        """scriptName:        Name of IdP script specified as the action for 
                              HTML forms
        smWSDLuri:            URI For Session Manager WSDL used for user
                              authentication
        smCertFilePath:     file path for Session Manager public key.  If
                              not set it will be retrieved using a 
                              Session Manager WS call.
        userName:             normally set from user input to form in
                              showLogin()
        passPhrase:           ditto"""

        self.smWSDLuri = smWSDLuri
        self._smClnt = None
        
        self.smCertFilePath = smCertFilePath
        
        self.userName = userName
        self.passPhrase = passPhrase
                                
        super(IdentityProviderSecurityCGI, self).__init__(scriptName,
                                                          **securityCGIKwArgs)

    
    #_________________________________________________________________________
    def processFields(self, **kwargs):
        """Call appropriate actions according to the fields set"""
   
        if self.authenticateTag in self:
            # User has entered login details - now authenticate using the 
            # Session Manager WS
            sessCookie = self._authenticate()
            
            if "authorise" in self:
                # Authorisation and authentication arguments were set - 
                # Now call authorisation passing the session cookie
                self._getAttCert(sessCookie)
            
            if self.returnURItag in self:
                # The authentication process is as a result of a redirect 
                # request from another site - redirect back to the remote site
                # returning the credentials contained in the NDG security
                self._processCredsRequest(sessCookie=sessCookie,
                                          setCookie=True, 
                                          **kwargs)
        elif self.returnURItag in self:
            # Identity provider receives request from remote site for 
            # credentials and returns them
            self._processCredsRequest(**kwargs)
                
        elif "authorise" in self:
            # Handle a get attribute certificate request
            self._getAttCert()
                    
        else:
            # Present login as the default behaviour
            self.showLogin(**kwargs)


    #_________________________________________________________________________
    def _processCredsRequest(self,
                             returnURI=None,
                             bAuthorise=False, 
                             sessCookie=None, 
                             **returnCredsResponseKwArgs):
        """Receive request from a Service Provider for credentials.  Process 
        and return via a redirect"""

        if returnURI is None:
            try:
                returnURI = self[self.returnURItag].value
                
            except KeyError, e:
                raise SecurityCGIError, \
                    "Processing credentials request:  %s is not set" % e
        
                                                     
        # Check for cookie in environment
        if sessCookie is None and 'HTTP_COOKIE' in os.environ:
    
            # Get session ID from existing cookie
            sessCookie = SimpleCookie(os.environ['HTTP_COOKIE'])
       

        # Check for NDG cookie
        if sessCookie and UserSession.isValidSecurityCookie(sessCookie):
                
            # Return cookie to requestor
            self._returnCredsResponse(sessCookie, 
                                      returnURI, 
                                      **returnCredsResponseKwArgs)

        else:
            # No cookie present - display login.  Submit must redirect back to
            # this script with '?authenticate=1&returnURI=<...>'
            self.showLogin(returnURI=returnURI,
                           bAuthorise=bAuthorise, 
                           pageTitle="NDG Login")

    
    #_________________________________________________________________________
    def _returnCredsResponse(self,
                             sessCookie, 
                             returnURI=None,
                             pageTitle='',
                             hdrTxt='',
                             delayTime=0,
                             redirectMsg='',
                             setCookie=False):
        """User's Identity Provider returns credentials to requestor via a 
        HTTP redirect
        
        sessCookie:   NDG Session cookie
        pageTitle:    Give the redirect page a title
        headTags:     Optionally add additional tags in <head/> section
        delayTime:    time in seconds before carrying out redirect - redirect
                      page will be displayed in this interval
        redirectMsg:  Message to put on redirect page.  Can be plain text or
                      formatted HTML
        setCookie:    Set to True to set the cookie in the IdP's target
                      domain.  This could be used in the case where the user
                      has just logged in but the session cookie has not been
                      set yet."""

        if returnURI is None:
            try:
                returnURI = self[self.returnURItag].value
            except KeyError:
                raise SecurityCGIError, \
                                "No returnURI set for return of credentials"
            
        # Check that the returnURI is over https, if not credentials would
        # be returned to the service provider in clear text and could be 
        # snooped.  The exception to this is where returnURI and IdP URI 
        # are in the same domain.  In this case credentials would not be 
        # passed between SP and IdP URIs anyway
        cookieDomain = sessCookie[UserSession.cookieTags[0]]['domain']
        if returnURI[0:6] != self._httpsSpecifier and \
           cookieDomain not in returnURI:           
            raise SecurityCGIError, "Specified returnURI must use HTTPS"

                                         
        cookieTxt = setCookie and sessCookie.output() + os.linesep or ''


        # Check to see if the returnURI is in the same domain - if so there's
        # no need to return any credentials in the redirect
        cookieDomain = sessCookie[UserSession.cookieTags[0]]['domain']
        if cookieDomain and cookieDomain in returnURI:
            credArgs = ''            
        else:
            # returnURI is in a different domain - return the credentials
            # Add credentials to URI but loop through so as to not have to 
            # refer to the tag names directly.  Tag names are abstracted 
            # behind the UserSession interface
            sessCookieArgs = '&'.join(["%s=%s" % (tag, sessCookie[tag].value)\
                                       for tag in UserSession.cookieTags])
            
            b64encExpiry = base64.urlsafe_b64encode(\
                            sessCookie[UserSession.cookieTags[0]]['expires'])

            # Nb. Allow for case where return URI already includes some args            
            credArgs = "%s%s&expires=%s" % \
            ('?' in returnURI and '&' or '?', sessCookieArgs, b64encExpiry)
                 
            
        print """Content-type: text/html
%s
<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH" content="%d; url=%s%s">
%s
</head>
<body>
%s
</body>
</html>""" % (cookieTxt, 
              pageTitle, 
              delayTime, 
              returnURI, 
              credArgs, 
              hdrTxt,
              redirectMsg)
    
    
    #_________________________________________________________________________
    def _authenticate(self, bAuthorise=False):
        """Authenticate username and passphrase input from preceeding login
        form

        bAuthorise: set to True so that if an error occurs, login will be
                    recalled followed by authorisation"""

        self.userName = 'userName' in self and self['userName'].value or None
        self.passPhrase = \
                    'passPhrase' in self and self['passPhrase'].value or None
                    
        returnURI = self.returnURItag in self and \
                                        self[self.returnURItag].value or None
            
            
        if self.userName is None:
            self.showLogin(returnURI=returnURI,
                           bAuthorise=bAuthorise,
                           pageTitle="Login - error no username set")
            raise SecurityCGIError, "no username set for authentication"

        if self.passPhrase is None:
            self.showLogin(returnURI=returnURI,
                           bAuthorise=bAuthorise,
                           pageTitle="Login - error no pass-phrase set")
            raise SecurityCGIError, "no pass-phrase set for authentication"


        # Instantiate WS proxy and request connection
        try:
            if not self._smClnt:
                self._smClnt = SessionClient(smWSDL=self.smWSDLuri,
                               smCertFilePath=self.smCertFilePath,
                               clntCertFilePath=self.clntCertFilePath,
                               clntPriKeyFilePath=self.clntPriKeyFilePath,
                               traceFile=self._wsDebug and sys.stderr or None)

            sSessCookie = self._smClnt.connect(userName=self.userName,
                                             pPhrase=self.passPhrase,
                                             clntPriKeyPwd=self.clntPriKeyPwd)
            sessCookie = SimpleCookie(sSessCookie)
            return sessCookie

        except Exception, e:
            self.showLogin(returnURI=returnURI,
                           bAuthorise=bAuthorise,
                           pageTitle="Login - internal error")
            raise SecurityCGIError, "Authenticating user: %s" % e

    
    #_________________________________________________________________________
    def showLogin(self,
                  scriptName=None,
                  returnURI=None,
                  contentTypeHdr=True,
                  htmlTag=True,
                  pageTitle='NDG Login',
                  hdrTxt=_defStyle,
                  headTag=True,
                  bodyTag=True,
                  bAuthorise=False):
        """Display initial NDG login form
        
        Override this method in a derived class in order to define a custom
        login with the required look and feel for the IdP organisation
        
        Derived class method MUST include the form field,
        
        IdentityProviderSecurityCGI.authenticateTag
        
        in order to correctly call this classes' _authenticate() method e.g.
        
        ...<input type=hidden name=%s value="1">...' % \
                                IdentityProviderSecurityCGI.authenticateTag
        """
    
        if scriptName:
            self.scriptName = scriptName
            
        if contentTypeHdr: print "Content-type: text/html\n\n"
        
        if htmlTag: print "<html>"
    
        if headTag:
            print """<head>
<title>%s</title>
%s
</head>""" % (pageTitle, hdrTxt)
    
    
        if bodyTag: print "<body>"


        if returnURI is None and self.returnURItag in self:
            returnURI = self[self.returnURItag].value

        if returnURI:
            returnURIfield = "<input type=hidden name=%s value=\"%s\">" % \
                                                (self.returnURItag, returnURI)
        else:
            returnURIfield = ''
        
    
        if bAuthorise:
            authoriseArg = "<input type=hidden name=authorise value=\"1\">"
        else:
            authoriseArg = ""
    
    
        # Set authorisation method default
        acMappingFlagChkBox = {}.fromkeys(self.acMappingFlags, '')
    
        if self.acMappingFlag is None:
            # Default to safest option for user
            acMappingFlagChkBox[self.acAllowMappingWithPrompt] = ' checked'
        else:
            acMappingFlagChkBox[self.acMappingFlag] = ' checked'
    
        print \
    """<script language="javascript">
    <!--
        function toggleLayer(layerId)
        {
            if (document.getElementById)
            {
                // Standard
                var style = document.getElementById(layerId).style;
            }
            else if (document.all)
            {
                // Old msie versions
                var style = document.all[whichLayer].style;
            }
            else if (document.layers)
            {
                // nn4
                var style = document.layers[whichLayer].style;
            }
            style.visibility = style.visibility == "visible" ? 
"hidden":"visible";        }
    //-->
    </script>
    <h3>NERC Data Grid Site Login (Test)<BR clear=all></h3>
    <hr>
    
    <form action="%s" method="POST">
    
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr><td>User Name:</td> <td><input type=text name=userName value="">
    </td></tr>
    <tr>
        <td>Password:</td>
        <td><input type=password name=passPhrase></td>
    </tr>
    <tr>
        <td colspan="2" align="right">
            <a href="javascript:toggleLayer('advSettings');">Advanced 
Settings</a>            <input type=submit value="Login">
        </td>
    </tr>
    <input type=hidden name=%s value="1">
    %s"""  % (self.scriptName, self.authenticateTag, returnURIfield)
    
        print \
    """</tbody></table>
    <br>
    <div id="advSettings" style="position: relative; visibility: hidden;">
        <h4>Role Mapping for access to other trusted sites</h4>
        <p>Your account has roles or <i>privileges</i> which determine what 
        data you have access to.  If you access data at another NDG trusted 
        site, these roles can be mapped to local roles at that site to help 
        you gain access:
        </p>   
        <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
        <tbody>
        <tr>
            <td>
                <input type="radio" name="authorisationMethod" value="%s"%s>
            </td>
            <td>
            Allow my roles to be mapped to local roles at other NDG trusted 
            sites.
            </td>
        </tr>
        <tr>
            <td>
                <input type="radio" name="authorisationMethod" value="%s"%s>
            </td>
            <td>
            Allow my roles to be mapped, but prompt me so that I may choose 
            which roles to map before gaining access.
            </td>
        <tr>
            <td>
                <input type="radio" name="authorisationMethod" value="%s"%s>
            </td>
            <td>
                Don't allow mapping of my roles.
            </td>
        </tr>
        </tbody>
        </table>
    </div>
    </form>
    """ % (self.acAllowMapping,
           acMappingFlagChkBox[self.acAllowMapping], 
           self.acAllowMappingWithPrompt,
           acMappingFlagChkBox[self.acAllowMappingWithPrompt],
           self.acNoMapping,
           acMappingFlagChkBox[self.acNoMapping])
    
        if bodyTag: print "</body>"
        if htmlTag: print "</html>"
    
        # end of showLogin()
