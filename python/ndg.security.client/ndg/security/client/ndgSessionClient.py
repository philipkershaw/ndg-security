#!/usr/bin/env python

"""NDG Session client script - makes requests for authentication and
authorisation

NERC Data Grid Project

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
__author__ = "P J Kershaw"
__date__ = "08/03/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = "$Id$"

# Command line processing
import sys
import os
import optparse
import re
import getpass

from Cookie import SimpleCookie

from ndg.security.client.SecurityClient import *


#_____________________________________________________________________________
def setSoapDebug(option, optStr, value, parser):
    """Parser Callback function for enabling SOAP debug output"""
    parser.values.soapDebug = sys.stderr

   
#_____________________________________________________________________________
def setSessCookie(option, optStr, value, parser):
    """Parser Callback function for reading session cookie from command line
    """
    try:
        parser.values.sessCookie = SimpleCookie(open(value).read().strip())
        
    except IOError, (errNo, errMsg):
        raise optparse.OptionValueError(\
                    "Reading cookie from file \"%s\": %s" % (value, errMsg))
                           
    except Exception, e:
        raise optparse.OptionValueError(\
                    "Reading cookie from file \"%s\": %s" % (value, str(e)))


#_____________________________________________________________________________
def setSessCookieFromStdin(option, optStr, value, parser):
    """Parser Callback function for reading cookie from stdin"""
    try:
        # Read from standard input
        parser.values.sessCookie = SimpleCookie(sys.stdin.read().strip())

    except KeyboardInterrupt:
        raise optparse.OptionValueError(\
                    "option \"%s\": expecting cookie set from stdin" % optStr)
          
    except Exception, e:
        raise optparse.OptionValueError(\
                    "option %s: Reading cookie from file \"%s\": %s" % \
                    (optStr, value, str(e)))
                    

#_____________________________________________________________________________
def setClntPriKeyPwd(option, optStr, value, parser):
    """Parser Callback function for reading client private key password"""

    try:
        parser.values.clntPriKeyPwd = open(value).read().strip()
        
    except IOError, (errNo, errMsg):
        raise optparse.OptionValueError(\
                    "Reading password from file \"%s\": %s" % (value, errMsg))
                           
    except Exception, e:
        raise optparse.OptionValueError(\
                    "Reading password from file \"%s\": %s" % (value, str(e)))
       

#_____________________________________________________________________________
def setAAcert(option, optStr, value, parser):
    """Parser callback function for reading Attribute Authority Public key"""
    
    try:
        parser.values.aaCert = open(value).read().strip()
        
    except IOError, (errNo, errMsg):
        raise optparse.OptionValueError(\
                "Reading Attribute Authority Public key file \"%s\": %s" % \
                (value, errMsg))
                           
    except Exception, e:
        raise optparse.OptionValueError(\
                "Reading Attribute Authority Public key file \"%s\": %s" % \
                (value, str(e)))
                
                      
#_____________________________________________________________________________
def main():

    usage = os.path.basename(sys.argv[0]) + " [--add-user=<username> ...]|"+\
            "[--connect=<username> ...]|[--req-attr ...]|" + \
            "[--connect=<username> ... --req-attr ...]"
            
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-n", 
                      "--add-user", 
                      dest="newUserName",
                      help="add a new user, see also: -p and -s options")

    parser.add_option("-c", 
                      "--connect",
                      dest="userName",
                      help="""login in to a Session Manager with username.""")
    
    parser.add_option("-r", 
                      "--req-attr", 
                      dest="attAuthorityURI", 
                      help=\
"""Get a Session Manager to request authorisation from an Attribute Authority 
with the given address.""")
    
    parser.add_option("-a", 
                      "--att-authority-pubkey-file",
                      action="callback",
                      callback=setAAcert,
                      dest="aaCert",
                      type="string", 
                      help=\
"""File Path of Public key of Attribute Authority used by the Session Manager 
to encrypt requests to it.  WARNING: If this is not set, requests will be sent
in clear text.""")

    parser.add_option("-x",
                      "--clnt-pubkey-file",
                      dest="clntCertFilePath",
                      help=\
"""X.509 Certificate of client.  This is used by the Session Manager to 
encrypt responses.  WARNING: If this is not set, the response will be sent 
back in clear text""")

    parser.add_option("-k",
                      "--clnt-prikey-file",
                      dest="clntPriKeyFilePath",
                      help=\
"""Private key file of client.  This is used by the client to decrypt
responses.  This must be set if -x/--clnt-pubkey-file is set.""")

    parser.add_option("-w",
                      "--clnt-prikey-pwd-file",
                      dest="clntPriKeyPwd",
                      action="callback",
                      callback=setClntPriKeyPwd,
                      type="string",
                      help=\
"""Pass a file containing the password for the client private key.  If not
set, it is prompted for from tty.""")

    parser.add_option("-y",
                      "--session-mgr-pubkey-file",
                      dest="smCertFilePath",
                      help=\
"""X.509 Certificate of Session Manager.  This is used to encrypt the request
to the Session Manager.  WARNING: if this is not set, the request will be sent
in clear text""")

    parser.add_option("-s",
                      "--session-mgr-uri",
                      dest="sessMgrURI",
                      help="Address of Session Manager to connect to")

    parser.add_option("-d",
                      "--soap-debug",
                      dest="soapDebug",
                      action="callback",
                      callback=setSoapDebug,
                      help="Print SOAP message output")

    parser.add_option("-p",
                      "--pass-phrase-from-stdin",
                      action="store_true",
                      dest="bPassPhraseFromStdin",
                      default=False,
                      help="""\
Take user's pass-phrase from stdin.  If this flag is omitted, pass-phrase is
prompted for from tty""")

    parser.add_option("-i",
                      "--cookie-file",
                      action="callback",
                      callback=setSessCookie,
                      type="string",
                      dest="sessCookie",
                      help=\
"""Session cookie for --req-attr/-r call.  This is returned from a previous
connect call (-c USERNAME/--connect=USERNAME).  Note that connect and request
authoirsation calls can be combined.  In this case, this arg is not needed as
the cookie is passed directly from the connect call output to the
authorisation request e.g. ... -c username -r -s "http://..." -a
"http://...""")

    parser.add_option("-e",
                      "--cookie-from-stdin",
                      action="callback",
                      callback=setSessCookieFromStdin,
                      dest="sessCookie",
                      help="Read session cookie from stdin.")

    parser.add_option("-m",
                      "--map-from-trusted-hosts",
                      action="store_true",
                      dest="mapFromTrustedHosts",
                      default=False,
                      help=\
"""For use with --req-attr/-r flag.  Set to allow the Session Manager to
automatically use Attribute Certificates from the user's wallet or, if no
suitable ones are found, to contact other trusted hosts in order to get
Attribute Certificates for mapping""")

    parser.add_option("-q",
                      "--req-role",
                      dest="reqRole",
                      help="""\
For use with --req-attr/-r flag.  Making certifcate mapping more efficient
by specifying to the Session Manager what role is needed for attribute
certificates from trusted hosts in order to get a mapped Attribute Certificate
back from the Attribute Authority""")

    parser.add_option("-l",
                      "--rtn-ext-att-cert-list",
                      action="store_true",
                      dest="rtnExtAttCertList",
                      default=False,
                      help=\
"""For use with --req-attr/-r flag.  Determines behaviour in the case where 
authorisation is denied by an Attribute Authority.  If set, a list of
candidate Attribute Certificates from trusted hosts will be returned.  Any one
of these could be re-input in a subsequent authorisation request by setting
the --ext-att-cert-list-file option.  The certificates can be used to obtain a
mapped Attribute Certificate from the import target Attribute Authority""")

    parser.add_option("-f",
                      "--ext-att-cert-list-file",
                      dest="extAttCertListFile",
                      help=\
"""For use with --req-attr/-r flag.  A file of concatenated Attribute
Certificates.  These are certificates from other import hosts trusted by the
Attribute Authority.  The Session Manager tries each in turn until the
Attribute Authority accepts one and uses it to create and return a mapped
Attribute Certificate""")
    
    parser.add_option("-t",
                      "--ext-trusted-hosts-file",
                      dest="extTrustedHostsFile",
                      help=\
"""For use with --req-attr/-r flag.  Pass a file containing a comma 
separarated list of hosts that are trusted by the Attribute Authority.  The
Session Manager will contact these hosts in turn, stopping when one of them
grants it an Attribute Certificate that it can present to the target Attribute
Authority in order to get a mapped Attribute Certificate in return.""")

    (options, args) = parser.parse_args()

    if not options.sessMgrURI:        
        sys.stderr.write("Error, No Session Manager WSDL URI set.\n\n")
        parser.print_help()
        return(1)
        
    passPhrase = None
   
    # For connect/addUser a pass-phrase is needed
    if options.newUserName or options.userName:
        
        if options.bPassPhraseFromStdin:
            # Read from standard input
            passPhrase = sys.stdin.read().strip()           
        else:
            # Obtain from prompt
            try:
                passPhrase = getpass.getpass(prompt="Login pass-phrase: ") 
            except KeyboardInterrupt:
                return(1)

    if options.clntPriKeyPwd is None and options.clntPriKeyFilePath:
        # Obtain from prompt
        try:
            options.clntPriKeyPwd = getpass.getpass(\
                                    prompt="Client private key pass-phrase: ") 
        except KeyboardInterrupt:
            return(1)

                  
    extAttCertList = None
                
    if options.extAttCertListFile:
        try:
            # Open and read file removing any <?xml ... ?> headers
            sExtAttCertListFile = open(options.extAttCertListFile).read()
            sAttCertTmp = re.sub("\s*<\?xml.*\?>\s*", "", sExtAttCertListFile)
            
            # Convert into a list
            extAttCertList = ['<attributeCertificate>' + ac for ac in \
                            sAttCertTmp.split('<attributeCertificate>')[1:]]
        except Exception, e:
            sys.stderr.write(\
                "Error parsing file \%s\" for option \"%s\": %s" % \
                (arg, "--ext-att-cert-list-file\"/\"-f", str(e)))

        
    extTrustedHostList = None

    if options.extTrustedHostsFile:
        try:
            extTrustedHostList = \
                re.split("\s*,\s*", open(options.extTrustedHostsFile).read())
            
        except Exception, e:
            sys.stderr.write(\
                "Error parsing file \%s\" for option \"%s\": %s" % \
                (arg, "--ext-trusted-host-file\"/\"-t", str(e)))


    # Initialise session client
    try:
        sessClnt = SessionMgrClient(smWSDL=options.sessMgrURI,
                             smCertFilePath=options.smCertFilePath,
                             clntCertFilePath=options.clntCertFilePath,
                             clntPriKeyFilePath=options.clntPriKeyFilePath,
                             tracefile=options.soapDebug)
    except Exception, e:
        sys.stderr.write("Initialising client: %s\n" % str(e))
        return(1)
    
    methodCall = False    
    try:
        if options.newUserName:
            methodCall = True
            
            sessClnt.addUser(userName=options.newUserName, 
                             pPhrase=passPhrase,
                             clntPriKeyPwd=options.clntPriKeyPwd)
            return(0)
                            
        if options.userName:
            methodCall = True
            
            sSessCookie = sessClnt.connect(userName=options.userName, 
                                       pPhrase=passPhrase,
                                       clntPriKeyPwd=options.clntPriKeyPwd)            
            print sSessCookie
            # Don't exit here - req-autho may have been set too
            
        if options.attAuthorityURI:
            methodCall = True

            if options.userName:
                # Connect was set also - parse cookie in order to session ID
                # and WSDL address
                options.sessCookie = SimpleCookie(sSessCookie)
                
            authResp = sessClnt.reqAuthorisation(\
                            sessCookie=options.sessCookie,
                            aaWSDL=options.attAuthorityURI,
                            aaCert=options.aaCert,
                            mapFromTrustedHosts=options.mapFromTrustedHosts,
                            reqRole=options.reqRole,
                            rtnExtAttCertList=options.rtnExtAttCertList,
                            extAttCertList=extAttCertList,
                            extTrustedHostList=extTrustedHostList,
                            clntPriKeyPwd=options.clntPriKeyPwd)
            print authResp
        
        if not methodCall:   
            sys.stderr.write("Set a flag to specify the web-service call " + \
                             "e.g. --connect=USERNAME\n\n")
            parser.print_help()
            return(1)
            
    except Exception, e:
        sys.stderr.write(str(e) + os.linesep)
     
    return(0)
