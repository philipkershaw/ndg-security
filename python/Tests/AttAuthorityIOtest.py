#!/bin/env python

import unittest
from NDG.AttAuthorityIO import *


class AttAuthorityIOtestCase(unittest.TestCase):
    
    def setUp(self):
        pass
    
    def tearDown(self):
        pass

    def testAuthorisationReq1(self):
        
        try:
            proxyCert = open("./proxy.pem").read().strip()

            userAttCert = \
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=AttributeAuthority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>4</issuerSerialNumber>
        <validity>
            <notBefore>2006 03 14 13 02 50</notBefore>
            <notAfter>2006 03 14 21 02 50</notAfter>
        </validity>
        <attributes>
            <roleSet>
                <role>
                    <name>government</name>
                </role>
            </roleSet>
        </attributes>
        <provenance>original</provenance>
    </acInfo>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>1c8njnV4ZcDjQKTnfc4Uoj7OUmg=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>cmuFVlzeJGV6hRIlJunDwcNdRApXP1aDtuXg1x0FWXjz9t2tEzCm2gqrb0p3hYEh
pcIwcHTh+yEjpqYSrRqabOqeRivLbfamDwmOWbxPfGzLsX8IrtwL6nDt72YoPhd0
PlpyXkz9l97Wykh8L2fPF9InTTnpUyZ0j34+lGFroPM=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIIB9TCCAV6gAwIBAgIBBDANBgkqhkiG9w0BAQQFADAwMQwwCgYDVQQKEwNOREcx
DTALBgNVBAsTBEJBREMxETAPBgNVBAMTCFNpbXBsZUNBMB4XDTA1MTEwMTE0Mjc1
OVoXDTA2MTEwMTE0Mjc1OVowOjEMMAoGA1UEChMDTkRHMQ0wCwYDVQQLEwRCQURD
MRswGQYDVQQDExJBdHRyaWJ1dGVBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBAJylt3cBDPDpFXfho8UM3WDEMm+yWDKeotwEj4oyWdP1ZeU0CQHz
fovJO/hFcqp6LeQKPir+WcDJoZhlX3rp4QQhRGL4ldATDJg/EXacu5wPnCkVnt3W
tlL930W97tY7JmyPO4uKNc5DAxt2XFOmU0hnHOGZon1rHpmo+HCf+aanAgMBAAGj
FTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAELYlxWcSb
Ifad6cVtXF2VCw+qoK7qSvqAHISPKTu5IxJoHVMlkQH7IJs73iIvXoKWuaP9zLY0
w5PaGn7077gPLIcSZhlI7wRb0JigmnJk/WTDjQUYQgDyPdJTGQQ1UqqjE4hYRFs4
brRl7KmdlZ4XFZqBgO2o2UTea3ZCcHSpsA==</X509Certificate>
<X509SubjectName>CN=AttributeAuthority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=SimpleCA,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>4</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>"""
      
            import pdb
            pdb.set_trace()
            self.authorisationReq = AuthorisationReq(proxyCert=proxyCert,
                                                     userAttCert=userAttCert)
            
        except Exception, e:
            self.fail(str(e))
            
        print self.authorisationReq()
        print self.authorisationReq['userAttCert']
 
 
    def testAuthorisationReq2(self):
        
        try:
            proxyCert = open("./proxy.pem").read().strip()

            userAttCert = ""
            
            self.authorisationReq = AuthorisationReq(proxyCert=proxyCert,
                                                     userAttCert=userAttCert)
            
        except Exception, e:
            self.fail(str(e))
            
        print self.authorisationReq()
        print self.authorisationReq['userAttCert']
                    

    def testAuthorisationReq3(self):
        """Test parsing of XML text input"""
        
        xmlTxt = \
"""<?xml version="1.0" encoding="UTF-8"?>
<AuthorisationReq>
    <userAttCert><attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=AttributeAuthority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>4</issuerSerialNumber>
        <validity>
            <notBefore>2006 03 14 13 02 50</notBefore>
            <notAfter>2006 03 14 21 02 50</notAfter>
        </validity>
        <attributes>
            <roleSet>
                <role>
                    <name>government</name>
                </role>
            </roleSet>
        </attributes>
        <provenance>original</provenance>
    </acInfo>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>1c8njnV4ZcDjQKTnfc4Uoj7OUmg=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>cmuFVlzeJGV6hRIlJunDwcNdRApXP1aDtuXg1x0FWXjz9t2tEzCm2gqrb0p3hYEh
pcIwcHTh+yEjpqYSrRqabOqeRivLbfamDwmOWbxPfGzLsX8IrtwL6nDt72YoPhd0
PlpyXkz9l97Wykh8L2fPF9InTTnpUyZ0j34+lGFroPM=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIIB9TCCAV6gAwIBAgIBBDANBgkqhkiG9w0BAQQFADAwMQwwCgYDVQQKEwNOREcx
DTALBgNVBAsTBEJBREMxETAPBgNVBAMTCFNpbXBsZUNBMB4XDTA1MTEwMTE0Mjc1
OVoXDTA2MTEwMTE0Mjc1OVowOjEMMAoGA1UEChMDTkRHMQ0wCwYDVQQLEwRCQURD
MRswGQYDVQQDExJBdHRyaWJ1dGVBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBAJylt3cBDPDpFXfho8UM3WDEMm+yWDKeotwEj4oyWdP1ZeU0CQHz
fovJO/hFcqp6LeQKPir+WcDJoZhlX3rp4QQhRGL4ldATDJg/EXacu5wPnCkVnt3W
tlL930W97tY7JmyPO4uKNc5DAxt2XFOmU0hnHOGZon1rHpmo+HCf+aanAgMBAAGj
FTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAELYlxWcSb
Ifad6cVtXF2VCw+qoK7qSvqAHISPKTu5IxJoHVMlkQH7IJs73iIvXoKWuaP9zLY0
w5PaGn7077gPLIcSZhlI7wRb0JigmnJk/WTDjQUYQgDyPdJTGQQ1UqqjE4hYRFs4
brRl7KmdlZ4XFZqBgO2o2UTea3ZCcHSpsA==</X509Certificate>
<X509SubjectName>CN=AttributeAuthority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=SimpleCA,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>4</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>
</userAttCert>
    <proxyCert>-----BEGIN CERTIFICATE-----
MIIBzTCCATagAwIBAgIES2vj2zANBgkqhkiG9w0BAQQFADAwMQwwCgYDVQQKEwNO
REcxDTALBgNVBAsTBEJBREMxETAPBgNVBAMTCHBqa2Vyc2hhMB4XDTA2MDMxNDE1
MTkwMFoXDTA2MDMxNDIzMjQwMFowRTEMMAoGA1UEChMDTkRHMQ0wCwYDVQQLEwRC
QURDMREwDwYDVQQDEwhwamtlcnNoYTETMBEGA1UEAxMKMTI2NTM2MTg4MzBcMA0G
CSqGSIb3DQEBAQUAA0sAMEgCQQDc0W/KBEjfzFH0ALnR68AM+u1ILbCVDBJ1p0BL
A/ibj0Qxu4xolPk3QApAgESNCH+HbIGx7yzcAm5duKyPa8zVAgMBAAGjIzAhMB8G
CisGAQQBm1ABgV4BAf8EDjAMMAoGCCsGAQUFBxUBMA0GCSqGSIb3DQEBBAUAA4GB
ABkpixdwOo+Uk9D5nRPAJnB3hmgt7rCP/C08167rgOl0X2rDZouLLbsBVEl+l9F9
9+CJ8kT0WpCXCXoezU+enowFkRUwBhtYh/0N680reB/P27CBTEyFwoI7VOVsFfEl
NeTl1weNqAR6kmQCZOGGjYXpZXhMx02aNglGw9ESsNih
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBANzRb8oESN/MUfQAudHrwAz67UgtsJUMEnWnQEsD+JuPRDG7jGiU
+TdACkCARI0If4dsgbHvLNwCbl24rI9rzNUCAwEAAQJAGy/6KJBQfKWGbZltR4hU
NATtFBb0B9Xdq/i0tMe/Yz+Mwc8Lt8ZEEL/dML/EqFQBKOPJmwHeZSo1ntcWlIaB
YQIhAP6Q/IAWNaD5a1byJQurLxKuxne1XGgs/aXv1TiC7eBNAiEA3g/Ld9kdZALy
8ALJE+LgEn4yywxLZyc+DkoD5WM6oqkCIHs24BB7L3/32Z2e3JF2TPWFBOkiLlT6
Gdd8az7MGKktAiEArW+EqPxoGh67g32JcwC1pXvvS+s0UUKzExH37QcNWtECIAkS
1oASKxQY2JppPCTa7JZDS2/oFDxILlTlRNhruB4m
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIB6zCCAVSgAwIBAgIBDDANBgkqhkiG9w0BAQQFADAwMQwwCgYDVQQKEwNOREcx
DTALBgNVBAsTBEJBREMxETAPBgNVBAMTCFNpbXBsZUNBMB4XDTA2MDEwNjE0MjYw
NloXDTA4MDEwNjE0MTE0NlowMDEMMAoGA1UEChMDTkRHMQ0wCwYDVQQLEwRCQURD
MREwDwYDVQQDEwhwamtlcnNoYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
yEj8Qz+yEHYKTLrQIOlayqWK9AVJu4k8ohfTrmORcNj8eoWJgJGe81Rr5zsimiqc
49neTwn0GDG3HWeNqQqFUsyrDttQOAc5aNtrFigvotj7yKAcnrpwDU1YISTNzJyi
3P3sLOYpDnkaurfEhKHjtEVavMHVp6jdzXZAE+sX510CAwEAAaMVMBMwEQYJYIZI
AYb4QgEBBAQDAgTwMA0GCSqGSIb3DQEBBAUAA4GBALNiZpIZQUOz25nBJeiOxCNi
dGGHZdDkHN7Bqq4XTjsaTRLFrkX0EqJHR/LtskUlRqeuJByYlt75XV3lesi/Xjcb
USAWTEl+NLY1JXp3Olrhk+Ialp8aIaM1hhG51wmRZFgmGN93RxiFhHIX3hlsRSdV
tbb57rWa5U6tlsforWg5
-----END CERTIFICATE-----
</proxyCert>
</AuthorisationReq>"""

        import pdb
        pdb.set_trace()
        try:
            self.authorisationReq = AuthorisationReq(xmlTxt=xmlTxt)
            
        except Exception, e:
            self.fail(str(e))
            
        print self.authorisationReq()
        print self.authorisationReq['userAttCert']

                    
    def testTrustedHosts1(self):
        
        th = {'BADC': {'wsdl': 'http://glue.badc.rl.ac.uk/attAuthority.wsdl',
              'role': ['government']}}        
        try:       
            self.trustedHostResp = TrustedHostInfoResp(trustedHosts=th)
        except Exception, e:
            self.fail(str(e))
            
        print self.trustedHostResp()
        print self.trustedHostResp['trustedHosts']


    def testTrustedHosts2(self):
        
        th = {'BADC': {'wsdl': 'http://glue.badc.rl.ac.uk/attAuthority.wsdl',
              'role': ['government']},
              'BODC': {'wsdl': 'http://livglue.bodc.ac.uk/attAuthority.wsdl',
              'role': ['staff', 'bodcUser']}}        
        try:       
            self.trustedHostResp = TrustedHostInfoResp(errMsg='', 
                                                       trustedHosts=th)
        except Exception, e:
            self.fail(str(e))
  
        print self.trustedHostResp()
        print self.trustedHostResp['trustedHosts']


    def testTrustedHosts3(self):
        
        xmlTxt = \
"""<?xml version="1.0" encoding="UTF-8"?>
<TrustedHostInfoResp>
    <trustedHosts>
        <trusted name="BADC">
            <wsdl>http://glue.badc.rl.ac.uk/attAuthority.wsdl</wsdl>
            <roleSet>
                <role>government</role>
            </roleSet>
        </trusted>
        <trusted name="BODC">
            <wsdl>http://livglue.bodc.ac.uk/attAuthority.wsdl</wsdl>
            <roleSet>
                <role>staff</role>
                <role>bodcUser</role>
            </roleSet>
        </trusted>
    </trustedHosts>
</TrustedHostInfoResp>"""

        try:       
            self.trustedHostResp = TrustedHostInfoResp(xmlTxt=xmlTxt)
        except Exception, e:
            self.fail(str(e))
  
        print self.trustedHostResp()
        print self.trustedHostResp['trustedHosts']
        

class AttAuthorityIOtestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(AttAuthorityIOtestCase,
                  (
#                    "testAuthorisationReq1",
#                    "testAuthorisationReq2",
                    "testAuthorisationReq3",
#                    "testTrustedHosts1",
#                    "testTrustedHosts2",
#                    "testTrustedHosts3"
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()