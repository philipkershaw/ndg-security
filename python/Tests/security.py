#!/usr/local/NDG/ActivePython-2.4/bin/python
"""NDG CGI security script
 
NERC Data Grid Project
 
P J Kershaw 14/09/05
 
Copyright (C) 2005 CCLRC & NERC
 
This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
import os
import sys
import cgi
import re

# Catch socket errors
import socket

from Cookie import SimpleCookie
from ZSI import ServiceProxy


from NDG.AttCert import *
from NDG.SessionClient import *


#_____________________________________________________________________________
class SecurityCGIError(Exception):

    def __init__(self, msg):

        self.__msg = msg

    def __str__(self):
        return self.__msg


#_____________________________________________________________________________
class SecurityCGI:
    """CGI for NDG authentication and authorisation"""
    
    def __init__(self,
                 smWSDL,
                 aaWSDL,
                 userName=None,
                 passPhrase=None,
                 smEncrPubKeyFilePath=None,
                 org=None,
		 bDebug=False):
        """Omit username, passphrase and org if running from CGI"""
        
        self.__aaWSDL = aaWSDL   
        self.__smWSDL = smWSDL   
        self.__userName = userName
        self.__passPhrase = passPhrase
        self.__smEncrPubKeyFilePath = smEncrPubKeyFilePath
        self.__bDebug = bDebug

        # Authenticating organisation
        self.__org = org

        # Flag taken from form radio button decides whether mapping is
        # allowed or not and if so, should the user be prompted for which
        # attribute certificate to submit
        self.__authorisationMethod = None

        self.__attCert = None
        
        
    #_________________________________________________________________________
    def cgi(self):        
        """Two stage process - login followed by authentication.  If
        authentication fails re-call login."""

        # Use userName field to flag authentication call        
        form = cgi.FieldStorage()
        bAuthorise = form.has_key("authorise")

        #sys.stderr.write("Form keys: %s\n" % ', '.join(form.keys()))

        if form.has_key("extTrustedHost"):
            extTrustedHost = form["extTrustedHost"].value
        else:
            extTrustedHost = ''
                
        if form.has_key("authorisationMethod"):
            self.__authorisationMethod = form["authorisationMethod"].value


        if form.has_key("addUser"):

            # Register new account
            if not form.has_key("userName") or not form["userName"].value:
                raise SecurityCGIError("No username set")
            
            if not form.has_key("passPhrase") or not form["passPhrase"].value:
                raise SecurityCGIError("No pass-phrase set")
            
            if not form.has_key("confirmPassPhrase") or \
               not form["confirmPassPhrase"].value:
                raise SecurityCGIError("No confirmation pass-phrase set")

            if form["passPhrase"].value != form["confirmPassPhrase"].value:
                raise SecurityCGIError(\
                    "Pass-phrase and confirmation pass-phrase don't agree")
                
            self.__userName = form["userName"].value
            self.__passPhrase = form["passPhrase"].value

            self.addUser()
            
        elif form.has_key("login") or not form.keys():
            
            # Login
            print "Content-type: text/html" + os.linesep
            self.showLogin(bAuthorise=bAuthorise, bodyTag=True)
            
        elif form.has_key("authenticate"):

            # Authentication
            if form.has_key("userName") and form["userName"].value:
                self.__userName = form["userName"].value
            
            if form.has_key("passPhrase") and form["passPhrase"].value:
                self.__passPhrase = form["passPhrase"].value
                
            if form.has_key("org") and form["org"].value:
                self.__org = form["org"].value

            if bAuthorise:
                                    
                # Authorisation and authentication arguments were set
                # - Call authentication first
                cookie = self.authenticate(setCookie=False)

                # Call authorisation passing the session ID for authorise to
                # set the cookie
                self.authorise(cookie, extTrustedHost=extTrustedHost)

            else:
                # Only the authentication flag was set - Call authentication
                # and set cookie
                self.authenticate()
                
        elif bAuthorise:
            self.authorise(extTrustedHost=extTrustedHost)

        elif form.has_key("cookie"):           
            self.setCookie(form['cookie'].value)
            
        else:
            raise SecurityCGIError(\
                            "None of the Form keys were recognised: %s" % \
                            ', '.join(form.keys()))
            

    #_________________________________________________________________________
    def showLogin(self,
                  bAuthorise=False,
                  htmlTag=False,
                  heading=None,
                  bodyTag=False):
        """Display initial NDG login form"""
        if htmlTag: print "<html>"
        
        if isinstance(heading, basestring):
            print """<head>
    <title>%s</title>
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>""" % heading


        if bodyTag: print "<body>"

        if bAuthorise:
            authoriseArg = "<input type=hidden name=authorise value=\"1\">"
        else:
            authoriseArg = ""


        # Set authorisation method default
        authorisationMethodChk = { "allowMapping":              '',
                                   "allowMappingWithPrompt" :   '',
                                   "noMapping":                 ''}

        if self.__authorisationMethod is None:
            # Default to safest option for user
            authorisationMethodChk["allowMappingWithPrompt"] = ' checked'
        else:
            authorisationMethodChk[self.__authorisationMethod] = ' checked'
        
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
        style.visibility = style.visibility == "visible" ? "hidden":"visible";
    }
//-->
</script>
<h3>NERC Data Grid Site Login (Test)<BR clear=all></h3>
<hr>

<form action="./security.cgi" method="POST">

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
        <a href="javascript:toggleLayer('advSettings');">Advanced Settings</a>
        <input type=submit value="Login">
    </td>
</tr>
<input type=hidden name=authenticate value="1">
%s"""  % authoriseArg

        print \
"""</tbody></table>
<br>
<div id="advSettings" style="position: relative; visibility: hidden;">
    <h4>Role Mapping for access to other trusted sites</h4>
    <p>Your account has roles or <i>privileges</i> which determine what data you have access to.  If you access data at another NDG trusted site, these roles can be mapped to local roles at that site to help you gain access:
    </p>
    <table bgcolor=#ADD8E6 cellspacing=0 border=0 cellpadding=5>
    <tbody>
    <tr>
	<td>
	    <input type="radio" name="authorisationMethod" value="allowMapping"%s>
	</td>
    	<td>
            Allow my roles to be mapped to local roles at other NDG trusted sites.
    	</td>
    </tr>
    <tr>
    	<td>
    	    <input type="radio" name="authorisationMethod" value="allowMappingWithPrompt"%s>
        </td>
	<td>
	    Allow my roles to be mapped, but prompt me so that I may choose which roles to map before gaining access.
	</td>
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
    def addUser(self):
        """Add a new NDG User account"""

        if self.__userName is None:
            raise SecurityCGIError("No username set")
        
        if self.__passPhrase is None:
            raise SecurityCGIError("No passphrase set")

        if self.__bDebug:
            traceFile = sys.stderr
        else:
            traceFile = None
           
        try:
            # Instantiate WS proxy and request connection
            try:
                smClient = SessionClient(
                        smWSDL=self.__smWSDL,
                        smEncrPubKeyFilePath=self.__smEncrPubKeyFilePath,
                        traceFile=traceFile)
                        

                smClient.addUser(userName=self.__userName,
                                 pPhrase=self.__passPhrase)
            except Exception, e:
                raise SecurityCGIError("Session Client: " + str(e))

            print \
"""Content-type: text/html

<head>
    <title>NDG User Registration (Test)</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>
<body>
    <p>New user %s registered</p>
</body>""" % self.__userName
        
        except Exception, e:
            # Re-display login screen
            print \
"""Content-type: text/html

<head>
    <title>NDG User Registration (Test)</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>

<body>
    <p>Registration failed for new user account %s: %s</p>""" % \
            (self.__userName, e)
            
            raise SecurityCGIError("User registration failed: %s" % e)
    
    
    #_________________________________________________________________________
    def authenticate(self, setCookie=True, bAuthorise=False):
        """Authenticate username and passphrase input from preceeding login
        form

        bAuthorise: set to True so that if an error occurs, login will be
                    recalled followed by authorisation"""

        if self.__bDebug:
            traceFile = sys.stderr
        else:
            traceFile = None

            
        try:
            if self.__userName is None:
                raise SecurityCGIError("no username set")

            if self.__passPhrase is None:
                raise SecurityCGIError("no pass-phrase input")
            
            # Instantiate WS proxy and request connection
            try:
                smClient = SessionClient(
                        smWSDL=self.__smWSDL,
                        smEncrPubKeyFilePath=self.__smEncrPubKeyFilePath,
                        traceFile=traceFile)

                sessCookie = smClient.connect(userName=self.__userName,
                                              pPhrase=self.__passPhrase) 
            except Exception, e:
                # Socket error returns tuple - reformat to just give msg
                raise SecurityCGIError("Session client: " + str(e))


	    if setCookie:
            	print \
"""Content-type: text/html
%s

<head>
    <title>NDG User Authentication (Test)</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>

<body>
    <p>User %s authenticated</p>
    <p>Cookie is: %s</p>
</body>""" % (sessCookie, self.__userName, sessCookie)
            return sessCookie
        
        except Exception, e:
            # Re-display login screen
            if self.__userName is None:
                msgFmt = ''
            else:
                msgFmt = " for user '%s'" % self.__userName
                
            print \
"""Content-type: text/html

<head>
    <title>NDG User Authentication (Test)</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>

<body>"""            
            self.showLogin(bAuthorise=bAuthorise)
            print \
"""<script>alert("Login error%s: %s")</script> 
</body>""" % (msgFmt, e)
            
            raise SecurityCGIError("Login failed: %s" % e)


    #_________________________________________________________________________
    def authorise(self,
                  cookie=None,
                  reqRole='nercFunded',
                  extTrustedHost=''):
        """Contact Attribute Authority to get Attribute Certificate for data
        access

        cookie:     cookie containing session ID
        reqRole:    required role to get authorisation - default to NERC for
                    testing"""

        if self.__bDebug:
            traceFile = sys.stderr
        else:
            traceFile = None


        if extTrustedHost:
            extTrustedHostList = [extTrustedHost]
        else:
            extTrustedHostList = ''


        extAttCertList = None   
        bSetCookie = False
        
                               
        try:
            # Check for session ID input
            if isinstance(cookie, basestring):
                bSetCookie = True

            elif 'HTTP_COOKIE' not in os.environ:
                # Check for session ID set in existing cookie
                    
                # Re-display login screen
                print "Content-type: text/html" + os.linesep                    
                self.showLogin(bAuthorise=True,
                               bodyTag=True,
                               heading="NDG User Authorisation (Test)")

                return
            else:
                cookie = os.environ['HTTP_COOKIE']
                
                
            # Get session ID from existing cookie
            cookieObj = SimpleCookie(cookie)
            if "NDG-ID1" not in cookieObj:
                raise SecurityCGIError(\
                            'Expecting "NDG-ID1" ID for session cookie')
                             
            if "NDG-ID2" not in cookieObj:
                raise SecurityCGIError(\
                            'Expecting "NDG-ID2" ID for session cookie') 


            if self.__authorisationMethod == 'allowMapping':
                bMapFromTrustedHosts = True                
            else:
                bMapFromTrustedHosts = False


            # Instantiate WS proxy and request authorisation
            try:
                smClient = SessionClient(
                            smWSDL=self.__smWSDL,
                            smEncrPubKeyFilePath=self.__smEncrPubKeyFilePath,
                            traceFile=traceFile)

                resp = smClient.reqAuthorisation(cookieObj["NDG-ID1"].value,
                                    cookieObj["NDG-ID2"].value,
                                    aaWSDL=self.__aaWSDL,
                                    reqRole=reqRole,
                                    mapFromTrustedHosts=bMapFromTrustedHosts,
                                    extTrustedHostList=extTrustedHostList)
            except Exception, e:
                # Socket error returns tuple - reformat to just give msg
                raise SecurityCGIError("Session client: " + str(e))

            if resp['statCode'] == 'AccessGranted':
                # Convert from unicode
                self.__attCert = str(resp['attCert'])
            
            elif resp['statCode'] == 'AccessDenied':
                
                if not resp['extAttCertList']:
                    raise SecurityCGIError(str(resp['errMsg']))

            elif resp['statCode'] == 'AccessError':
                raise SecurityCGIError(str(resp['errMsg']))


            # Handle access denied/granted
            if bSetCookie:
                cookieTxt = cookie + os.linesep
            else:
                cookieTxt = ''
                
            print \
"""Content-type: text/html
%s

<head>
    <Title>NDG User Authorisation (Test)</Title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>

<body>""" % cookieTxt 

            if self.__attCert:
                
                # Get data using certificate obtained
                print "<p>User authorised</p>"
                print "<p>Attribute Certificate: <br>%s</p>" % \
                      re.sub("<", "&lt;", re.sub(">", "&gt;", self.__attCert))
                
            elif 'extAttCertList' in resp:
                # Display available certificates from other AAs in a table
                self.showExtAttCertSelect(resp['extAttCertList'])
                
            print "</body>" 

        except Exception, e:
                       
            # Re-display login screen
            print \
"""Content-type: text/html

<head>
    <title>NDG User Authorisation (Test)</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>

<body>"""
            
            self.showLogin(bAuthorise=True)
            print \
"""<script>alert("Authorisation failed: %s")</script>
</body>""" % e
            
            raise SecurityCGIError("Authorisation failed: %s" % e)
    

    def showAttCert(self, attCert=None):
        """Make a page to display Attribute Certificate"""
        if attCert is not None:
            self.__attCert = attCert


        
        if self.__attCert is None:
            print \
"""Content-type: text/html

<head>
    <title>NDG User Authorisation (Test)</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>

<body>
    <p>No Attribute Certificate set</p>
</body>"""
            return
        
        print \
"""Content-type: text/xml

%s""" % self.__attCert
            

    #_________________________________________________________________________
    def showExtAttCertSelect(self,
                             extAttCertList,
                             htmlTag=False,
                             heading=None,
                             bodyTag=False):
        """Display table for selection of external attribute certificates for
        mapping"""
        if htmlTag: print "<html>"
        
        if isinstance(heading, basestring):
            print """<head>
    <title>%s</title>
    <style type="text/css">
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
        body { font-family: Verdana, sans-serif; font-size: 10}
        table { font-family: Verdana, sans-serif; font-size: 10}
    -->
    </style>
</head>""" % heading

        sys.stderr.write("extAttCertList: \n\n%s\n" % extAttCertList)
        
        # Display title and table first row
        #
        # Form contains hidden fields so that on submit, authorisation is
        # called to get authorisation via a mapped certificate
        print \
"""<h2>NDG Data Access</h2>
<hr style="width: 100%; height: 2px;"><br>
<p>Select a certificate to allow access to data:</p>
<form action="./security.cgi" method="post">
    <input type=hidden name=authorise value="1">
    <input type=hidden name=authorisationMethod value="allowMapping">
    <table style="width: 100%;" border="0" cellpadding="10"
    cellspacing="1">
        <tbody>
        <tr bgcolor="#d5d5de">
            <td style="text-align: left; vertical-align: top;">
                <br>
            </td>
            <td style="width: 10px; text-align: left; vertical-align: top;">
                <span style="font-weight: bold;">Issuer</span>
            </td>
            <td style="text-align: left; vertical-align: top;">
                <span style="font-weight: bold;">Available Roles</span>
            </td>
        </tr>"""

        # Display available certificates - one in each row
        chkTxt = ['' for i in range(len(extAttCertList))]
        chkTxt[0] = ' checked'
        
        for sCert in extAttCertList:

            cert = AttCertParse(sCert)

            # Nb. hidden field authorisationMethod set to allowMapping so that
            # authorisation request can be made again but this time with the
            # s
            print """
        <tr bgcolor="#e2e2e2">
            <td style="vertical-align: top;">
                <input type="radio" name="extTrustedHost"
                value="%s"%s><br>
            </td>
            <td style="width: 20px;" valign="top">
                %s<br>
            </td>
            <td valign="top" width="80%%">
                %s<br>
            </td>
        </tr>
""" % (cert['issuerName'],
       chkTxt.pop(),
       cert['issuerName'],
       ', '.join(cert.getRoles()))

        print \
"""        <tr bgcolor="#d5d5de">
            <td colspan="3" align="right">
                <input type=submit value="   OK   ">
                <input type=button value="Cancel"
                 onClick="javascript:window.close();">
            </td>
        </tr>
        </tbody>
    </table>
</form>
"""
        
        if bodyTag: print "</body>"
        if htmlTag: print "</html>"

    # end of showExtAttCertSelect()



    #_________________________________________________________________________
    def setCookie(self, cookie):
        """Set a page with input cookie"""
        print "Content-type: text/html"
        print cookie



        
#_____________________________________________________________________________
if __name__ == "__main__":
    
    smWSDL = "http://glue.badc.rl.ac.uk/sessionMgr.wsdl"
    aaWSDL = "http://glue.badc.rl.ac.uk/attAuthority.wsdl"
    smPubKey = "/usr/local/NDG/conf/certs/badc-sm-cert.pem"
    

    # Instantiate and call CGI
    security = SecurityCGI(smWSDL,
                           aaWSDL,
#                           smEncrPubKeyFilePath=smPubKey,
			   bDebug=False)
    security.cgi()
