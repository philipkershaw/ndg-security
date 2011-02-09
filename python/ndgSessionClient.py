#!/usr/bin/env python

"""NDG Session client script - makes requests for authentication and
authorisation

NERC Data Grid Project

P J Kershaw 08/03/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
# Command line processing
import sys
import os
import getopt
import re

from NDG.SessionClient import *


#_____________________________________________________________________________
def usage(fp=sys.stdout):
    """Describes how to call session client from the command line"""
    progName = os.path.basename(sys.argv[0])
    
    fp.write(\
    """usage: %s [--add-user|--connect|--req-autho]|[--connect --req-autho]
        [<args...>]%s""" % (progName, os.linesep))
        
    fp.write("""    
-h | --help
    print usage summary

Web-service calls:
    
-n | --add-user
    add a new user: 
        
    %s --add-user -u <username> [-p] -s <Session Manager WSDL URI>

-c | --connect
    login in to a Session Manager
    
    %s --connect -u <username> [-p] -s <Session Manager WSDL URI>
    
-r | --req-autho
    Get a Session Manager to request authorisation from an Attribute 
    Authority on behalf of a user: 
    
    %s --req-autho -i <User's Session ID> -s <Session Manager WSDL URI> 
    -a <Attribute Authority WSDL URI> [-m -q <role name> -l -f <file path>
    -t <file path>]
  
Generic options:
    
-s <Session Manager WSDL URI> | 
 --session-mgr-wsdl-uri=<Session Manager WSDL URI>
    Address of Session Manager to connect to.
      
-d  | --soap-debug
    Print SOAP message output.

Options specific to --connect and --add-user:
    
-u <username> | --username=<username>
    username for --connect call

-p | --pass-phrase-from-stdin
    Take user's pass-phrase from stdin.  If this flag is omitted, pass-phrase 
    is prompted for.

Options specific to --req-autho:
    
-i <session ID> | --sessionID=<Session ID>
    Session ID for --req-autho call.  Session ID is obtained from the cookie
    returned from previous call to "%s --connect ..."
    
-e <encrypted Session Manager WSDL URI> | 
 --encr-sess-mgr-wsdl-uri <encrypted Session Manager WSDL URI>
    Encrypted address of Session Manager where user session is held.  This is
    obtained from the cookie returned from call to "%s --connect ..."
    
-a <Attribute Authority WSDL URI> | 
 --att-authority-wsdl-uri=<Attribute Authority WSDL URI>
    The address of the Attribute Authority from which to request an 
    Attribute Certificate.

-m | --map-from-trusted-hosts
    Set to allow the Session Manager to automatically use Attribute 
    Certificates from the user's wallet or if no suitable ones are found,
    to contact other trusted hosts in order to get Attribute Certificates
    for mapping.
    
-q <role name> | --req-role=<role name>
    Give a hint to the authorisation request as to what role is needed in 
    order to get a mapped Attribute Certificate back from the Attribute 
    Authority.
    
-l | --rtn-ext-att-cert-list
    Determines behaviour for where authorisation is denied by an Attribute
    Authority.   If set, a list of candidate Attribute Certificates from
    trusted import hosts will be returned.  Any one of these could be
    re-input in a subsequent with the --ext-att-cert-list-file option in order
    to get a mapped Attribute Certificate
    
-f <file path> | --ext-att-cert-list-file=<file path>
    file of concatenated Attribute Certificates.  These are certificates
    from other import hosts trusted by the Attribute Authority.  The Session
    Manager tries each in turn until the Attribute Authority accepts one 
    and uses it to create and return a mapped Attribute Certificate.
    
-t | --ext-trusted-host-file=<comma separated variable file>
    For use with --req-autho flag.  Pass a file containing a list of hosts
    trusted by the Attribute Authority.  The Session Manager will contact 
    these hosts in turn until it can get an Attribute Certificate to pass
    to the Attribute Authority to get a mapped Attribute Certificate in 
    return.
""" % (progName, progName, progName, progName, progName))


#_____________________________________________________________________________
if __name__ == '__main__':

    try:
        optLongNames = [ "help",
                         "add-user", 
                         "connect",
                         "req-autho",
                         "session-mgr-wsdl-uri=", 
                         "att-authority-wsdl-uri=",
                         "username=",
                         "pass-phrase-from-stdin",
                         "session-id=",
                         "encr-sess-mgr-wsdl-uri",
                         "soap-debug",
                         "map-from-trusted-hosts",
                         "req-role=",
                         "rtn-ext-att-cert-list",
                         "ext-att-cert-list-file=",
                         "ext-trusted-host-file="]
        optShortNames = "hncrs:a:u:pi:e:dmq:lf:t:"
        opts, args = getopt.getopt(sys.argv[1:], optShortNames, optLongNames)

    except getopt.GetoptError, e:
        sys.stderr.write("Error: %s\n\n" % e)
        usage(fp=sys.stderr)
        sys.exit(1)

    # Use long options to make a dictionary
    argDict = {}.fromkeys([opt.split('=')[0] for opt in optLongNames])
    
    extTrustedHostList = None
    extAttCertList = None
    passPhrase = None
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(0)

        elif opt in ("-n", "--add-user"):
            argDict['add-user'] = True

        elif opt in ("-c", "--connect"):
            argDict['connect'] = True

        elif opt in ("-r", "--req-autho"):
            argDict['req-autho'] = True

        elif opt in ("-s", "--session-mgr-wsdl-uri"):
            argDict['session-mgr-wsdl-uri'] = arg

        elif opt in ("-a", "--att-authority-wsdl-uri"):
            argDict['att-authority-wsdl-uri'] = arg

        elif opt in ("-u", "--username"):
            argDict['username'] = arg

        elif opt in ("-p", "--pass-phrase-from-stdin"):
            argDict['pass-phrase-from-stdin'] = True

        elif opt in ("-i", "--session-id"):
            argDict['session-id'] = arg

        elif opt in ("-e", "--encr-sess-mgr-wsdl-uri"):
            argDict['encr-sess-mgr-wsdl-uri'] = arg

        elif opt in ("-d", "--soap-debug"):
            argDict['soap-debug'] = sys.stderr

        elif opt in ("-m", "--map-from-trusted-hosts"):
            argDict['map-from-trusted-hosts'] = True
                
        elif opt in ("-q", "--req-role"):
            argDict['req-role'] = arg
        
        elif opt in ("-l", "--rtn-ext-att-cert-list"):
            argDict['rtn-ext-att-cert-list'] = True
            
        elif opt in ("-f", "--ext-att-cert-list-file"):
            argDict['ext-att-cert-list-file'] = arg
            
            try:
                # Open and read file removing any <?xml ... ?> headers
                fpExtAttCertList = open(argDict['ext-att-cert-list-file'])
                sAttCertList = \
                     re.sub("\s*<\?xml.*\?>\s*", "", fpExtAttCertList.read())
                
                # Convert into a list
                extAttCertList = ['<attributeCertificate>' + ac for ac in \
                            sAttCertList.split('<attributeCertificate>')[1:]]
            except Exception, e:
                sys.stderr.write(\
                    "Error parsing file \%s\" for option \"%s\": %s" % \
                    (arg, opt, str(e)))
            
        elif opt in ("-t", "ext-trusted-host-file"):
            try:
                extTrustedHostList = \
                    re.split("\s*,\s*",
                             open(argDict['ext-trusted-host-file']).read())
                
            except Exception, e:
                sys.stderr.write(\
                    "Error parsing file \%s\" for option \"%s\": %s" % \
                    (arg, opt, str(e)))
                    
        else:
            sys.stderr.write("Option not recognised: %s\n\n" % opt)
            usage(fp=sys.stderr)
            sys.exit(1)


    # For connect/addUser a pass-phrase is needed
    if argDict['add-user'] or argDict['connect']:
        
        if argDict['pass-phrase-from-stdin']:
            # Read from standard input
            passPhrase = sys.stdin.read().strip()
            
        else:
            # Obtain from prompt
            import getpass
            try:
#                passPhrase = getpass.getpass(prompt="pass-phrase: ") 
                passPhrase = open('./Tests/tmp').read().strip()
            except KeyboardInterrupt:
                sys.exit(1)


    # Initialise session client
    try:
        sessClnt = SessionClient(smWSDL=argDict['session-mgr-wsdl-uri'],
                                 traceFile=argDict['soap-debug'])
    except Exception, e:
        sys.stderr.write("Initialising client: %s\n" % str(e))
        sys.exit(1)
        
    try:
        if argDict['add-user']:
            sessClnt.addUser(userName=argDict['username'], pPhrase=passPhrase)
            sys.exit(0)
                            
        if argDict['connect']:
            sSessCookie = sessClnt.connect(userName=argDict['username'], 
                                           pPhrase=passPhrase)            
            print sSessCookie
            # Don't exit here - req-autho may have been set too
    
        if argDict['req-autho']:
            if argDict['connect']:
                # Connect was set also - parse cookie in order to session ID
                # and WSDL address
                from Cookie import SimpleCookie
                sessCookie = SimpleCookie(sSessCookie)
                
                argDict['session-id'] = sessCookie['NDG-ID1'].value
                argDict['encr-sess-mgr-wsdl-uri']=sessCookie['NDG-ID2'].value
                
            authResp = sessClnt.reqAuthorisation(\
                        sessID=argDict['session-id'], 
                        encrSessMgrWSDLuri=argDict['encr-sess-mgr-wsdl-uri'],
                        aaWSDL=argDict['att-authority-wsdl-uri'],
                        mapFromTrustedHosts=argDict['map-from-trusted-hosts'],
                        reqRole=argDict['req-role'],
                        rtnExtAttCertList=argDict['rtn-ext-att-cert-list'],
                        extAttCertList=extAttCertList,
                        extTrustedHostList=extTrustedHostList)
            print authResp
        else:   
            sys.stderr.write(\
            "Set a flag to specify the web-service call e.g. --connect\n\n")
            usage(fp=sys.stderr)
            sys.exit(1)
            
    except Exception, e:
        sys.stderr.write(str(e) + os.linesep)
     
    sys.exit(0)
