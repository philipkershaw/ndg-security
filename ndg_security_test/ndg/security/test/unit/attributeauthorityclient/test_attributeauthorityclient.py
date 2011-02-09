#!/usr/bin/env python
"""NDG Attribute Authority SOAP client unit tests

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/05/05, major update 16/01/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:test_attributeauthorityclient.py 4372 2008-10-29 09:45:39Z pjkersha $'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os, re
    
from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'], file)

from datetime import datetime
from uuid import uuid4
from xml.etree import ElementTree

from ndg.security.test.unit import BaseTestCase, mkDataDirPath

from ndg.security.common.utils.etree import prettyPrint

from ndg.security.common.attributeauthority import (AttributeAuthorityClient, 
                                                NoMatchingRoleInTrustedHosts)
from ndg.security.common.AttCert import AttCertRead
from ndg.security.common.X509 import X509CertParse, X509CertRead
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)

from saml.common.xml import SAMLConstants
from saml.saml2.core import (Attribute, SAMLVersion, Subject, NameID, Issuer, 
                             AttributeQuery, XSStringAttributeValue, StatusCode)
from saml.xml.etree import ResponseElementTree

from ndg.security.common.saml_utils.bindings import SOAPBinding as \
                                                            SamlSoapBinding
from ndg.security.common.saml_utils.bindings import AttributeQuerySOAPBinding
from ndg.security.common.saml_utils.bindings import AttributeQuerySslSOAPBinding
from ndg.security.common.saml_utils.esg import (EsgSamlNamespaces, 
                                                XSGroupRoleAttributeValue,
                                                EsgDefaultQueryAttributes)


class AttributeAuthorityClientBaseTestCase(BaseTestCase):
    def __init__(self, *arg, **kw):
        super(AttributeAuthorityClientBaseTestCase, self).__init__(*arg, **kw)

        if 'NDGSEC_AACLNT_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_AACLNT_UNITTEST_DIR'
                       ] = os.path.abspath(os.path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        self.cfgFilePath = jnPath(os.environ['NDGSEC_AACLNT_UNITTEST_DIR'],
                                  'attAuthorityClientTest.cfg')
        self.cfgParser.read(self.cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections():
            self.cfg[section] = dict(self.cfgParser.items(section))

        try:
            self.sslCACertList = [X509CertRead(xpdVars(caFile)) 
                                  for caFile in self.cfg['setUp'][
                                            'sslcaCertFilePathList'].split()]
        except KeyError:
            self.sslCACertList = []
            
        self.startAttributeAuthorities()        
      
      
class AttributeAuthorityClientTestCase(AttributeAuthorityClientBaseTestCase):
    clntPriKeyPwd = None
    pemPat = "-----BEGIN CERTIFICATE-----[^\-]*-----END CERTIFICATE-----"

    def _getCertChainFromProxyCertFile(self, proxyCertFilePath):
        '''Read proxy cert and user cert from a single PEM file and put in
        a list ready for input into SignatureHandler'''               
        proxyCertFileTxt = open(proxyCertFilePath).read()
        
        pemPatRE = re.compile(self.__class__.pemPat, re.S)
        x509CertList = pemPatRE.findall(proxyCertFileTxt)
        
        signingCertChain = [X509CertParse(x509Cert) 
                            for x509Cert in x509CertList]
    
        # Expecting proxy cert first - move this to the end.  This will
        # be the cert used to verify the message signature
        signingCertChain.reverse()
        
        return signingCertChain

    def setUp(self):
        super(AttributeAuthorityClientTestCase, self).setUp()
                
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
            
        thisSection = self.cfg['setUp']
        
        # Instantiate WS proxy
        self.siteAClnt = AttributeAuthorityClient(uri=thisSection['uri'],
                                sslPeerCertCN=thisSection.get('sslPeerCertCN'),
                                sslCACertList=self.sslCACertList,
                                cfgFileSection='wsse',
                                cfg=self.cfgParser)            

    def test01GetHostInfo(self):
        """test01GetHostInfo: retrieve info for AA host"""
        hostInfo = self.siteAClnt.getHostInfo()
        print "Host Info:\n %s" % hostInfo        

    def test02GetTrustedHostInfo(self):
        """test02GetTrustedHostInfo: retrieve trusted host info matching a
        given role"""
        trustedHostInfo = self.siteAClnt.getTrustedHostInfo(
                                 self.cfg['test02GetTrustedHostInfo']['role'])
        for hostname, hostInfo in trustedHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")

        print "Trusted Host Info:\n %s" % trustedHostInfo

    def test03GetTrustedHostInfoWithNoMatchingRoleFound(self):
        """test03GetTrustedHostInfoWithNoMatchingRoleFound: test the case 
        where the input role doesn't match any roles in the target AA's map 
        config file"""
        _cfg = self.cfg['test03GetTrustedHostInfoWithNoMatchingRoleFound']
        try:
            trustedHostInfo = self.siteAClnt.getTrustedHostInfo(_cfg['role'])
            self.fail("Expecting NoMatchingRoleInTrustedHosts exception")
            
        except NoMatchingRoleInTrustedHosts, e:
            print('As expected - no match for role "%s": %s' % 
                  (_cfg['role'], e))


    def test04GetTrustedHostInfoWithNoRole(self):
        """test04GetTrustedHostInfoWithNoRole: retrieve trusted host info 
        irrespective of role"""
        trustedHostInfo = self.siteAClnt.getTrustedHostInfo()
        for hostname, hostInfo in trustedHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")
                   
        print "Trusted Host Info:\n %s" % trustedHostInfo
        

    def test05GetAllHostsInfo(self):
        """test05GetAllHostsInfo: retrieve info for all hosts"""
        allHostInfo = self.siteAClnt.getAllHostsInfo()
        for hostname, hostInfo in allHostInfo.items():
            self.assert_(hostname, "Hostname not set")
            for k, v in hostInfo.items():
                self.assert_(k, "hostInfo value key unset")
                   
        print "All Hosts Info:\n %s" % allHostInfo


    def test06GetAttCert(self):        
        """test06GetAttCert: Request attribute certificate from NDG Attribute 
        Authority Web Service."""
        _cfg = self.cfg['test06GetAttCert']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % 
                            (ioErr.filename, ioErr.strerror))

        # Make attribute certificate request
        attCert = self.siteAClnt.getAttCert(userX509Cert=userX509CertTxt)
        
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(_cfg['attCertFilePath'])
        attCert.write()
        
        
    def test07GetAttCertWithUserIdSet(self):        
        """test07GetAttCertWithUserIdSet: Request attribute certificate from 
        NDG Attribute Authority Web Service setting a specific user Id 
        independent of the signer of the SOAP request."""
        _cfg = self.cfg['test07GetAttCertWithUserIdSet']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % 
                            (ioErr.filename, ioErr.strerror))

        # Make attribute certificate request
        userId = _cfg['userId']
        attCert = self.siteAClnt.getAttCert(userId=userId,
                                            userX509Cert=userX509CertTxt)
        
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(_cfg['attCertFilePath'])
        attCert.write()


    def test08GetMappedAttCert(self):        
        """test08GetMappedAttCert: Request mapped attribute certificate from 
        NDG Attribute Authority Web Service."""
        _cfg = self.cfg['test08GetMappedAttCert']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % \
                                    (ioErr.filename, ioErr.strerror))
    
        # Simlarly for Attribute Certificate 
        try:
            userAttCert = AttCertRead(xpdVars(_cfg['userAttCertFilePath']))
            
        except IOError, ioErr:
            raise Exception("Error reading attribute certificate file \"%s\": "
                            "%s" % (ioErr.filename, ioErr.strerror))
        
        # Make client to site B Attribute Authority
        siteBClnt = AttributeAuthorityClient(uri=_cfg['uri'], 
                                       cfgFileSection='wsse',
                                       cfg=self.cfgParser)
    
        # Make attribute certificate request
        attCert = siteBClnt.getAttCert(userX509Cert=userX509CertTxt,
                                       userAttCert=userAttCert)
        print "Attribute Certificate: \n\n:" + str(attCert)
        
        attCert.filePath = xpdVars(_cfg['mappedAttCertFilePath'])
        attCert.write()
        
        
    def test09GetMappedAttCertStressTest(self):        
        """test09GetMappedAttCertStressTest: Request mapped attribute 
        certificate from NDG Attribute Authority Web Service."""
        _cfg = self.cfg['test09GetMappedAttCertStressTest']
        
        # Read user Certificate into a string ready for passing via WS
        try:
            userX509CertFilePath = xpdVars(_cfg.get('issuingClntCertFilePath'))
            userX509CertTxt = open(userX509CertFilePath, 'r').read()
        
        except TypeError:
            # No issuing cert set
            userX509CertTxt = None
                
        except IOError, ioErr:
            raise Exception("Error reading certificate file \"%s\": %s" % 
                                    (ioErr.filename, ioErr.strerror))

        # Make client to site B Attribute Authority
        siteBClnt = AttributeAuthorityClient(uri=_cfg['uri'], 
                                       cfgFileSection='wsse',
                                       cfg=self.cfgParser)

        acFilePathList = [xpdVars(file) for file in \
                          _cfg['userAttCertFilePathList'].split()]

        for acFilePath in acFilePathList:
            try:
                userAttCert = AttCertRead(acFilePath)
                
            except IOError, ioErr:
                raise Exception("Error reading attribute certificate file "
                                '"%s": %s' % (ioErr.filename, ioErr.strerror))
        
            # Make attribute certificate request
            try:
                attCert = siteBClnt.getAttCert(userX509Cert=userX509CertTxt,
                                               userAttCert=userAttCert)
            except Exception, e:
                outFilePfx = 'test09GetMappedAttCertStressTest-%s' % \
                        os.path.basename(acFilePath)    
                msgFile = open(outFilePfx+".msg", 'w')
                msgFile.write('Failed for "%s": %s\n' % (acFilePath, e))

   
class AttributeAuthoritySAMLInterfaceTestCase(
                                        AttributeAuthorityClientBaseTestCase):
    """Separate class for Attribute Authority SAML Attribute Query interface"""
    
    def __init__(self, *arg, **kw):
        super(AttributeAuthoritySAMLInterfaceTestCase, self).__init__(*arg, 
                                                                      **kw)
        self.startSiteAAttributeAuthority(withSSL=True, port=5443)
       
    def test01SAMLAttributeQuery(self):
        _cfg = self.cfg['test01SAMLAttributeQuery']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME
        fnAttribute = Attribute()
        fnAttribute.name = EsgSamlNamespaces.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = xsStringNs
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        lnAttribute = Attribute()
        lnAttribute.name = EsgSamlNamespaces.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = xsStringNs
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = EsgSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = xsStringNs
        emailAddressAttribute.friendlyName = "emailAddress"
        
        attributeQuery.attributes.append(emailAddressAttribute) 

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SamlSoapBinding()
        response = binding.send(attributeQuery, _cfg['uri'])
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
        
        # Check Query ID matches the query ID the service received
        self.assert_(response.inResponseTo == attributeQuery.id)
        
        now = datetime.utcnow()
        self.assert_(response.issueInstant < now)
        self.assert_(response.assertions[-1].issueInstant < now)        
        self.assert_(response.assertions[-1].conditions.notBefore < now) 
        self.assert_(response.assertions[-1].conditions.notOnOrAfter > now)
         
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
             
    def test02SAMLAttributeQueryInvalidIssuer(self):
        _cfg = self.cfg['test02SAMLAttributeQueryInvalidIssuer']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "Invalid Site"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SamlSoapBinding()
        response = binding.send(attributeQuery, _cfg['uri'])

        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(
            response.status.statusCode.value==StatusCode.REQUEST_DENIED_URI)
                    
    def test03SAMLAttributeQueryUnknownSubject(self):
        _cfg = self.cfg['test03SAMLAttributeQueryUnknownSubject']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SamlSoapBinding()
        response = binding.send(attributeQuery, _cfg['uri'])
        
        samlResponseElem = ResponseElementTree.toXML(response)
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(
            response.status.statusCode.value==StatusCode.UNKNOWN_PRINCIPAL_URI)
             
    def test04SAMLAttributeQueryInvalidAttrName(self):
        _cfg = self.cfg['test04SAMLAttributeQueryInvalidAttrName']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = EsgSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        invalidAttribute = Attribute()
        invalidAttribute.name = "myInvalidAttributeName"
        invalidAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(invalidAttribute) 

        binding = SamlSoapBinding()
        response = binding.send(attributeQuery, _cfg['uri'])
        
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==\
                     StatusCode.INVALID_ATTR_NAME_VALUE_URI)
        
    def test05AttributeQuerySOAPBindingInterface(self):
        _cfg = self.cfg['test05AttributeQuerySOAPBindingInterface']
        
        binding = AttributeQuerySOAPBinding()
        
        binding.subjectID = AttributeAuthoritySAMLInterfaceTestCase.OPENID_URI
        binding.issuerDN = \
            AttributeAuthoritySAMLInterfaceTestCase.VALID_REQUESTOR_IDS[0]        
        
        binding.queryAttributes = EsgDefaultQueryAttributes.ATTRIBUTES
        
        response = binding.send(uri=_cfg['uri'])
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)

    def test06AttributeQueryFromConfig(self):
        thisSection = 'test06AttributeQueryFromConfig'
        _cfg = self.cfg[thisSection]
        
        binding = AttributeQuerySOAPBinding.fromConfig(self.cfgFilePath, 
                                                       section=thisSection,
                                                       prefix='attributeQuery.')
        binding.subjectID = _cfg['subject']
        response = binding.send(uri=_cfg['uri'])
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
        
    def test07AttributeQuerySslSOAPBindingInterface(self):
        thisSection = 'test07AttributeQuerySslSOAPBindingInterface'
        _cfg = self.cfg[thisSection]
        
        binding = AttributeQuerySslSOAPBinding.fromConfig(self.cfgFilePath, 
                                                       section=thisSection,
                                                       prefix='attributeQuery.')
        
        binding.subjectID = _cfg['subject']
        response = binding.send(uri=_cfg['uri'])
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
        
if __name__ == "__main__":
    unittest.main()
