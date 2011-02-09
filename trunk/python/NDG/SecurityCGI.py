#!/usr/bin/env python

"""NDG Security CGI services

NERC Data Grid Project

P J Kershaw 23/05/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
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

    def __init__(self, msg):
        self.__msg = msg
         
    def __str__(self):
        return self.__msg

   
class SecurityCGI(cgi.FieldStorage):
    """CGI interface class for NDG Security
    
    Terms used throughout:        
        remote site     - where user is accessing resources
        home site       - where user's credentials are held or they login"""

    #_________________________________________________________________________
    def __init__(self,
                 smWSDL,
                 aaWSDL,
                 smPubKeyFilePath=None,
                 aaPubKeyFilePath=None,
                 clntPubKeyFilePath=None,
                 clntPriKeyFilePath=None,
                 clntPriKeyPwd=None,
                 userName=None,
                 passPhrase=None,
                 scriptName=None,
                 trustedHostInfo=None,
                 cookieLifetimeHrs=8,
                 wsDebug=False,
                 **cgiFieldStorageKwArgs):
        """scriptName:        name of script to call in forms - defaults to
                              this file.  Modify if you inherit from this
                              class.
        smWSDL:               URI For Session Manager WSDL used for user
                              authentication
        aaWSDL:               URI for Attribute Authority WSDL used to get a
                              list of login URI for trusted hosts
        trustedHostInfo:      dictionary of URIs for trusted hosts indexed by
                              hostname
        cookieLifetimeHrs:    cookie lifetime in hours
        wsDebug:              print output from WS transactions to stderr"""

        self.smWSDL = smWSDL
        self.smClnt = None
        self.aaWSDL = aaWSDL
        self.aaClnt = None
        
        self.userName = userName
        self.passPhrase = passPhrase
        
        self.smPubKeyFilePath = smPubKeyFilePath
        self.aaPubKeyFilePath = aaPubKeyFilePath
        
        self.clntPubKeyFilePath = clntPubKeyFilePath
        self.clntPriKeyFilePath = clntPriKeyFilePath
        self.clntPriKeyPwd = clntPriKeyPwd

        if scriptName:
            self.scriptName = scriptName
        else:
            self.scriptName = __file__

        self.trustedHostInfo = trustedHostInfo
        self.cookieLifetimeHrs = cookieLifetimeHrs

        # Work out expiry time offset from the time this script is run
        self.dtCookieExpiry = datetime.utcnow() + \
                            timedelta(seconds=self.cookieLifetimeHrs*60*60)

        self.__wsDebug = False        
        self._authorisationMethod = None
        self.attCert = None
                
        cgi.FieldStorage.__init__(self, **cgiFieldStorageKwArgs)

 
    #_________________________________________________________________________
    def processFields(self, **kwargs):
        """Call appropriate actions according to the fields set"""

        bAuthorise = "authorise" in self
        
        if 'requestURI' in self:
            # Request credentials from user's home site
            self.requestCreds(**kwargs)

        elif 'NDG-ID1' in self and 'NDG-ID2' in self:
            # Receive credentials back from home site and set a new cookie at
            # remote site
            if 'expires' in self:
                encodedExpiry = self['expires'].value
            else:
                encodedExpiry = None

            self.receiveCredsResponse(self['NDG-ID1'].value,
                                      self['NDG-ID2'].value,
                                      encodedExpiry=encodedExpiry,
                                      **kwargs)

        elif 'authenticate' in self:
            # User has entered login details - now authenticate using the 
            # Session Manager WS
            sessCookie = self.authenticate()
            
            if bAuthorise:
                # Authorisation and authentication arguments were set
                # - Call authentication first
                sessCookie = self.authenticate(setCookie=False)

                # Call authorisation passing the session ID for authorise to
                # set the cookie
                self.getAttCert(sessCookie)
            
            if 'returnURI' in self:
                # The authentication process is as a result of a redirect 
                # request from another site - redirect back to the remote site
                # returning the credentials contained in the NDG security
                self.processCredsRequest(sessCookie=sessCookie,
                                         setCookie=True, 
                                         **kwargs)
                
        elif bAuthorise:
            self.getAttCert()
                    
        elif 'returnURI' in self:
            # Home site receives request from remote site for credentials and
            # returns them
            self.processCredsRequest(**kwargs)
        else:
            # Remote site presents possible sites for user to get their 
            # credentials from
            self.showHomeSiteSelect(**kwargs)
    
    
    #_________________________________________________________________________
    # Use instance name as an alias to processFields method
    __call__ = processFields
    

    #_________________________________________________________________________
    def _requestCreds(self,
                      requestURI=None,
                      returnURI=None,
                      pageTitle='',
                      headTags='',
                      delayTime=0,
                      redirectMsg=''):
        """Request credentials from a user's home site
        
        requestURI:   site to request credentials from - default is 
                      'requestURI' CGI form value
        pageTitle:    Give the redirect page a title
        headTags:     Optionally add additional tags in <head/> section
        delayTime:    time in seconds before carrying out redirect - redirect
                      page will be displayed in this interval
        redirectMsg:  Message to put on redirect page.  Can be plain text or
                      formatted HTML"""

        if returnURI is None:
            returnURI = self['returnURI'].value

        if requestURI is None:
            requestURI = self['requestURI'].value

        print """Content-type: text/html

<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH" content="%d; url=%s?returnURI=%s">
%s
</head>
<body>
%s
</body>
</html>""" % \
    (pageTitle, delayTime, requestURI, returnURI, headTags, redirectMsg)


    #_________________________________________________________________________
    def _receiveCredsResponse(self,
                              sessID,
                              sessMgrURI,
                              encodedExpiry=None,
                              **showCredsReceivedKwArgs):
        """Remote site receives returned credentials and creates a new cookie
        for its domain"""
        sessCookie = self.createCookie(sessID, sessMgrURI, encodedExpiry)
        self.showCredsReceived(sessCookie)

    #_________________________________________________________________________
    def showCredsReceived(self, 
                          sessCookie, 
                          pageTitle='', 
                          hdrTxt='', 
                          bodyTxt=''):
        """Called from receiveCredsResponse() once a cookie has been created.
        Makes a page to set the cookie and display to the user that they have
        been authenticated.  Derived class should override this method as
        required"""
        print """Content-type: text/html"
%s

<html>
<head>
<title>%s</title>
%s
</head>
<body>
    %s
</body>
</html>""" % (sessCookie.output(), pageTitle, hdrTxt, bodyTxt)

    
    #_________________________________________________________________________
    def _createCookie(self, sessID, sessMgrURI, encodedExpiry=None):
        """Convert credentials passed over URI from users home site into a new
        cookie"""

        if encodedExpiry:
            # Expiry is taken from encoded value passed over URI
            dtExpiry = None
            expiryStr = base64.urlsafe_b64decode(encodedExpiry)
        else:
            # Expiry is set from life time in hours input in __init__
            dtExpiry = self.dtCookieExpiry
            expiryStr = None

        return UserSession.createSecurityCookie(sessID,
                                                sessMgrURI,
                                                dtExpiry=dtExpiry,
                                                expiryStr=expiryStr)


	#_________________________________________________________________________
    def _processCredsRequest(self,
                             returnURI=None,
                             bAuthorise=False, 
                             sessCookie=None, 
                             **returnCredsResponseKwArgs):
        """Receive request from remote site for credentials.  Process and 
        return via a redirect"""

        if returnURI is None:
            returnURI = self['returnURI'].value
                                                         
        # Check for cookie in environment
        if sessCookie is None and 'HTTP_COOKIE' in os.environ:
    
            # Get session ID from existing cookie
            sessCookie = SimpleCookie(os.environ['HTTP_COOKIE'])

        # Check for NDG cookie
        if sessCookie and UserSession.isValidSecurityCookie(sessCookie):
                
            # Return cookie to requestor
            self.returnCredsResponse(sessCookie, 
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
        """User's home site returns credentials to requestor via a HTTP 
        redirect
        
        sessCookie:   NDG Session cookie
        pageTitle:    Give the redirect page a title
        headTags:     Optionally add additional tags in <head/> section
        delayTime:    time in seconds before carrying out redirect - redirect
                      page will be displayed in this interval
        redirectMsg:  Message to put on redirect page.  Can be plain text or
                      formatted HTML"""

        if returnURI is None:
            returnURI = self['returnURI'].value
                                         
        if setCookie:
            cookieTxt = sessCookie.output() + os.linesep
        else:
            cookieTxt = ''

        # Check to see if the returnURI is in the same domain - if so there's
        # no need to return any credentials in the redirect
        cookieDomain = sessCookie[UserSession.cookieTags[0]]['domain']
        if cookieDomain and cookieDomain in returnURI:
            print """Content-type: text/html
%s
<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH"
content="%d; url=%s">
%s
</head>
<body>
%s
</body>
</html>""" % ( cookieTxt,
               pageTitle,
               delayTime,
               returnURI,
               hdrTxt,
               redirectMsg)
            
        else:
            # returnURI is in a different domain - return the credentials
            #
            # Allow for case where return URI already includes some args
            if '?' in returnURI:
                argSeparator = '&'
            else:
                argSeparator = '?'
    
    
            print """Content-type: text/html
%s
<html>
<head>
<title>%s</title>
<meta http-equiv="REFRESH"
content="%d; url=%s%sNDG-ID1=%s&NDG-ID2=%s&expires=%s">
%s
</head>
<body>
%s
</body>
</html>""" % ( cookieTxt,
               pageTitle,
               delayTime,
               returnURI,
               argSeparator,
               sessCookie['NDG-ID1'].value,
               sessCookie['NDG-ID2'].value,
               base64.urlsafe_b64encode(sessCookie['NDG-ID1']['expires']),
               hdrTxt,
               redirectMsg)
    
    
    #_________________________________________________________________________
    def _authenticate(self, bAuthorise=False):
        """Authenticate username and passphrase input from preceeding login
        form

        bAuthorise: set to True so that if an error occurs, login will be
                    recalled followed by authorisation"""

        if self.__wsDebug:
            traceFile = sys.stderr
        else:
            traceFile = None


        if 'userName' in self:
            self.userName = self['userName'].value
            
        if 'passPhrase' in self:
            self.passPhrase = self['passPhrase'].value
            
        if 'returnURI' in self:
            returnURI = self['returnURI'].value
        else:
            returnURI = None
            
            
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
            if not self.smClnt:
                self.smClnt = SessionClient(smWSDL=self.smWSDL,
                                   smPubKeyFilePath=self.smPubKeyFilePath,
                                   clntPubKeyFilePath=self.clntPubKeyFilePath,
                                   clntPriKeyFilePath=self.clntPriKeyFilePath,
                                   traceFile=traceFile)

            sSessCookie = self.smClnt.connect(userName=self.userName,
                                         pPhrase=self.passPhrase,
                                         clntPriKeyPwd=self.clntPriKeyPwd)
            sessCookie = SimpleCookie(sSessCookie)
            return sessCookie

        except Exception, e:
            self.showLogin(returnURI=returnURI,
                           bAuthorise=bAuthorise,
                           pageTitle="Login - internal error")
            raise SecurityCGIError, "Session client: " + str(e)


    #_________________________________________________________________________
    def _getAttCert(self, sessCookie=None, reqRole=None):
        """Contact Attribute Authority to get Attribute Certificate for data
        access

        sessCookie:     NDG security session cookie
        reqRole:        specify the required role to get authorisation.  Set
                        this to optimise the process for getting the required
                        AC from a trusted host in order to perform mapping"""

        if self.__wsDebug:
            traceFile = sys.stderr
        else:
            traceFile = None


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
        if self._authorisationMethod == 'allowMapping':
            bMapFromTrustedHosts = True
            bRtnExtAttCertList = False

        elif self._authorisationMethod == 'allowMappingWithPrompt':
            bMapFromTrustedHosts = False
            bRtnExtAttCertList = True
        else:
            bMapFromTrustedHosts = False
            bRtnExtAttCertList = False


        # Instantiate WS proxy and request authorisation
        try:
            if not self.smClnt:
                self.smClnt = SessionClient(
                                smWSDL=self.smWSDL,
                                smPubKeyFilePath=self.smPubKeyFilePath,
                                clntPubKeyFilePath=self.clntPubKeyFilePath,
                                clntPriKeyFilePath=self.clntPriKeyFilePath,
                                traceFile=traceFile)

            resp = self.smClnt.reqAuthorisation(sessCookie=sessCookie,
                                aaWSDL=self.aaWSDL,
                                aaPubKey=self.aaPubKey,
                                reqRole=reqRole,
                                mapFromTrustedHosts=bMapFromTrustedHosts,
                                rtnExtAttCertList=bRtnExtAttCertList,
                                clntPriKeyPwd=self.clntPriKeyPwd)
        except Exception, e:
            # Socket error returns tuple - reformat to just give msg
            raise SecurityCGIError, "Session client: " + str(e)


        if resp['statCode'] == 'AccessGranted':
            self.onAttCertGranted(resp['attCert'])
        
        elif resp['statCode'] == 'AccessDenied':
            self.onAttCertDenied(resp['extAttCertList'], resp['errMsg'])
            
        elif resp['statCode'] == 'AccessError':
            raise SecurityCGIError, resp['errMsg']
            
    
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
            if contentTypeHdr:
                print "Content-type: text/html\n\n"
                    
            if htmlTag:
                print "<html>\n"
    
            if hdrTag:            
                if not hdrTxt:
                    hdrTxt = """    <style type=\"text/css\">
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

                print """<head>
            
    <title>%s</title>
    %s
</head>""" % (pageTitle, hdrTxt)
    
    
                if bodyTag:
                    print "<body>\n"
                
                print """
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
    </form>"""

                if bodyTag:
                    print "</body>\n"
        
                if htmlTag:
                    print "</html>\n"
    
        # end of handleAttCertDenied()

    
    #_________________________________________________________________________
    def showLogin(self,
                  returnURI=None,
                  contentTypeHdr=True,
                  htmlTag=True,
                  pageTitle='',
                  hdrTxt='',
                  headTag=True,
                  bodyTag=True,
                  bAuthorise=False):
        """Display initial NDG login form"""
    
        if contentTypeHdr: print "Content-type: text/html\n\n"
        
        if htmlTag: print "<html>"
    
        if headTag:
            if not hdrTxt:
                hdrTxt = """    <style type=\"text/css\">
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
                    
            print """<head>
        <title>%s</title>
        %s
    </head>""" % (pageTitle, hdrTxt)
    
    
        if bodyTag: print "<body>"


        if returnURI is None and 'returnURI' in self:
            returnURI = self['returnURI'].value

        if returnURI:
            returnURIfield = \
                "<input type=hidden name=returnURI value=\"%s\">" % returnURI
        else:
            returnURIfield = ''
        
    
        if bAuthorise:
            authoriseArg = "<input type=hidden name=authorise value=\"1\">"
        else:
            authoriseArg = ""
    
    
        # Set authorisation method default
        authorisationMethodChk = {  "allowMapping":              '',
                                    "allowMappingWithPrompt" :   '',
                                    "noMapping":                 ''}
    
        if self._authorisationMethod is None:
            # Default to safest option for user
            authorisationMethodChk["allowMappingWithPrompt"] = ' checked'
        else:
            authorisationMethodChk[self._authorisationMethod] = ' checked'
    
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
    <input type=hidden name=authenticate value="1">
    %s"""  % (self.scriptName, returnURIfield)
    
        print \
    """</tbody></table>
    <br>
    <div id="advSettings" style="position: relative; visibility: hidden;">
        <h4>Role Mapping for access to other trusted sites</h4>
        <p>Your account has roles or <i>privileges</i> which determine what data 
you have access to.  If you access data at another NDG trusted site, these roles 
can be mapped to local roles at that site to help you gain access:        </p>   
     <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>        <tbody>
        <tr>
        <td>
            <input type="radio" name="authorisationMethod" 
value="allowMapping"%s>        </td>
            <td>
                Allow my roles to be mapped to local roles at other NDG trusted 
sites.            </td>
        </tr>
        <tr>
            <td>
                <input type="radio" name="authorisationMethod" 
value="allowMappingWithPrompt"%s>            </td>
        <td>
            Allow my roles to be mapped, but prompt me so that I may choose 
which roles to map before gaining access.        </td>
        <tr>
        <td>
            <input type="radio" name="authorisationMethod" value="noMapping"%s>
        </td>
        <td>
            Don't allow mapping of my roles.
        </td>
        </tr>
        </tbody>
        </table>
    </div>
    </form>
    """ % (authorisationMethodChk['allowMapping'], \
           authorisationMethodChk['allowMappingWithPrompt'], \
           authorisationMethodChk['noMapping'])
    
        if bodyTag: print "</body>"
        if htmlTag: print "</html>"
    
        # end of showLogin()
    
    
    #_________________________________________________________________________
    def showHomeSiteSelect(self,
                           trustedHostInfo=None,
                           scriptName=None,
                           contentTypeHdr=False,
                           htmlTag=False,
                           hdrTag=False,
                           hdrTxt='',
                           bodyTag=False,
                           pageTitle=""):

        if trustedHostInfo:
            self.trustedHostInfo = trustedHostInfo

        if not self.trustedHostInfo:
            self.getTrustedHostInfo()
            
        if scriptName:
            self.scriptName = scriptName
            
                
        if contentTypeHdr:
            print "Content-type: text/html\n\n"
                
        if htmlTag:
            print "<html>\n"

        if hdrTag:            
            if not hdrTxt:
                hdrTxt = """    <style type=\"text/css\">
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

            print """<head>
            
    <title>%s</title>
    %s
</head>""" % (pageTitle, hdrTxt)
    
    
        if bodyTag:
            print "<body>\n"

            print """
    <form action="%s" method="POST">
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr>
      <td>
        <select name="requestURI">        
          <option value="">Select your home site...""" % self.scriptName
          
            for hostname, info in self.trustedHostInfo.items():
                print "<option value=\"%s\">%s" % (info['loginURI'], hostname)
                
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
            print "</body>\n"

        if htmlTag:
            print "</html>\n"
    
        # end of showHomeSiteSelect()


    #_________________________________________________________________________
    def getTrustedHostInfo(self):
        """Call Attribute Authority to find out trusted hosts.  These can be
        use to populate list for use to select home site for login"""
        
        if self.__wsDebug:
            traceFile = sys.stderr
        else:
            traceFile = None

        try:
            if not self.aaClnt:
                self.aaClnt = AttAuthorityClient(aaWSDL=self.aaWSDL,
                                aaPubKeyFilePath=self.aaPubKeyFilePath,
                                clntPubKeyFilePath=self.clntPubKeyFilePath,
                                clntPriKeyFilePath=self.clntPriKeyFilePath,
                                traceFile=traceFile)
            
            self.trustedHostInfo = self.aaClnt.getTrustedHostInfo(
                                           clntPriKeyPwd=self.clntPriKeyPwd)
        except Exception, e:
            raise SecurityCGIError, "Attribute Authority client: " + str(e)
