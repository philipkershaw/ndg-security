"""NDG Session Manager Web service server side interface.  Generated and 
adapted from:

wsdl2dispatch -f sessionMgr.wsdl

NERC Data Grid Project

P J Kershaw 18/12/05

Copyright (C) 2005 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

from ZSI.ServiceContainer import ServiceSOAPBinding

# wsdl2py generated
from sessionMgr_services import *

from Session import *

# Create custom XML formatted error response where needed
from SessionMgrIO import *


class sessionMgr(ServiceSOAPBinding):
    soapAction = {
        'urn:sessionMgr#addUser': 'soap_addUser',
        'urn:sessionMgr#connect': 'soap_connect',
        'urn:sessionMgr#reqAuthorisation': 'soap_reqAuthorisation',
        }

    def __init__(self, srv, debug=False, post='/sessionMgr.wsdl', **kw):
        
        ServiceSOAPBinding.__init__(self, post)

        # Link WS to underlying session manager class instance
        if not isinstance(srv, SessionMgr):
            SessionMgrError("Expecting SessionMgr type")
            
        self.__srv = srv
        
        self.__debug = debug
        
        
    #_________________________________________________________________________
    def soap_addUser(self, ps):
        """SOAP interface to NDG Session Manager WS addUser."""
       
        if self.__debug:
            import pdb
            pdb.set_trace()

        # input vals in request object
        reqArgs = ps.Parse(addUserRequestWrapper)
        reqTxt = str(reqArgs._addUserReq)

        # assign return values to response object
        resp = addUserResponseWrapper()
        
        
        # Request a connection from the Session Manager
        try:
            resp._addUserResp = self.__srv.addUser(reqXMLtxt=reqTxt)
               
        except Exception, e:
            resp._addUserResp = str(AddUserResp(errMsg=str(e)))

        return resp


    #_________________________________________________________________________
    def soap_connect(self, ps):
        """SOAP interface to NDG Session Manager WS connect."""
        
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        # input vals in request object
        reqArgs = ps.Parse(connectRequestWrapper)
        reqTxt = str(reqArgs._connectReq)

        # assign return values to response object
        resp = connectResponseWrapper()
        
        
        # Request a connection from the Session Manager
        try:
            resp._connectResp = self.__srv.connect(reqXMLtxt=reqTxt) 
              
        except Exception, e:
            resp._connectResp = str(ConnectResp(errMsg=str(e)))
        
        return resp


    #_________________________________________________________________________
    def soap_reqAuthorisation(self, ps):
        
        if self.__debug:
            import pdb
            pdb.set_trace()
            
        # input vals in request object
        reqArgs = ps.Parse(authorisationRequestWrapper)
        reqTxt = str(reqArgs._authorisationReq)
        
        # assign return values to response object
        resp = authorisationResponseWrapper()


        # Make an authorisation request via the session manager
        try:
            authResp = self.__srv.reqAuthorisation(reqXMLtxt=reqTxt)
            
        except Exception, e:
            authResp=AuthorisationResp(statCode=AuthorisationResp.accessError,
                                       errMsg=str(e))
                                       
        # Convert response into XML formatted string    
        resp._authorisationResp = str(authResp)
                                                            
        return resp

