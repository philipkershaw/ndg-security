"""NDG Attribute Authority Web service server side interface.  Generated and 
adapted from:

wsdl2dispatch -f attAuthority.wsdl

NERC Data Grid Project

P J Kershaw 19/01/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""

cvsID = '$Id$'

from attAuthority_services import *
from ZSI.ServiceContainer import ServiceSOAPBinding

from AttAuthority import *

# Create custom XML formatted error response where needed
from AttAuthorityIO import *


class attAuthority(ServiceSOAPBinding):
    soapAction = {
        'urn:attAuthority#getTrustedHostInfo': 'soap_getTrustedHostInfo',
        'urn:attAuthority#reqAuthorisation': 'soap_reqAuthorisation',
        }

    def __init__(self, srv, debug=False, post='/attAuthority.wsdl', **kw):
        
        ServiceSOAPBinding.__init__(self, post)

        # Link WS to underlying attribute authority class instance
        if not isinstance(srv, AttAuthority):
            AttAuthorityError("Expecting AttAuthority type")
            
        self.__srv = srv
        
        self.__debug = debug
        

    #_________________________________________________________________________
    def soap_getTrustedHostInfo(self, ps):
       
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        # input vals in request object
        reqArgs = ps.Parse(trustedHostInfoRequestWrapper)
        reqTxt = str(reqArgs._trustedHostInfoReq)
        
        # assign return values to response object
        resp = trustedHostInfoResponseWrapper()
        
        
        try:
            resp._trustedHostInfoResp = self.__srv.getTrustedHostInfo(\
                                                                reqTxt=reqTxt)   
        except Exception, e:
            resp._trustedHostInfoResp=str(TrustedHostInfoResp(errMsg=str(e)))

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
        
        
        try:
            attCert = self.__srv.authorise(reqXMLtxt=reqTxt)
            
            authorisationResp = AuthorisationResp(\
                                    credential=attCert,
                                    statCode=AuthorisationResp.accessGranted)
            
        except AttAuthorityAccessDenied, e:
            authorisationResp = AuthorisationResp(errMsg=str(e),
                                    statCode=AuthorisationResp.accessDenied)
            
        except Exception, e:
            authorisationResp = AuthorisationResp(errMsg=str(e),
                                    statCode=AuthorisationResp.accessError)
        
        
        resp._authorisationResp = str(authorisationResp)
        return resp
