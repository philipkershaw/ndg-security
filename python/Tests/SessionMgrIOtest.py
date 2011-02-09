#!/bin/env python

import unittest
from ndg.security.SessionMgrIO import *


class sessionMgrIOtestCase(unittest.TestCase):
    
    def setUp(self):
        pass
    
    def tearDown(self):
        pass
                                        
    def testConnectReq1(self):
        # Client side - Set up input for SessionMgr WSDL connect()
        cr = ConnectReq(userName="WileECoyote", 
                        pPhrase="ACME Road Runner catcher", 
                        encrPubKeyFilePath="../certs/badc-aa-cert.pem")

    def testConnectReq2(self):
        # Server side - decrypt connectReq from connect() request
        cr = ConnectReq(\
                  encrXMLtxt=open("../Tests/xmlsec/connectReq.xml").read(),
                  encrPriKeyFilePath="../certs/badc-aa-key.pem",
                  encrPriKeyPwd="    ")

    def testConnectResp1(self):
        # Server side - make a connect response message
        cr1 = ConnectResp(sessCookie="A proxy certificate")

    def testConnectResp2(self):
        cr2 = ConnectResp(sessCookie="A session cookie", 
                          encrPubKeyFilePath="../certs/badc-aa-cert.pem")

    
    def testAuthorisationReq1(self):
    
        extAttCertList = [\
"""<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=AttributeAuthority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>4</issuerSerialNumber>
        <validity>
            <notBefore>2006 04 03 09 09 26</notBefore>
            <notAfter>2006 04 03 17 08 25</notAfter>
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
<DigestValue>As4JwG1ABH5sA0vO7cOvGJK/PgQ=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>ECtPnRoQJFmWi91xaksaRxhrEweCdEc0+LOkdDlhCzfjRy8QxNogvc3spRKEn817
GVa3YLNLE3/UUZAxa4o+F4nI5WkGDFpnVyhfgA7dhhDL3khL1WKumGA303bqn0Ti
oK+T+rZ23VjFLtrvQjkwbh8gzyAgIFQL29ifIlu3hLk=</SignatureValue>
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
</Signature></attributeCertificate>""",
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 16 11 53 36</notBefore> 
        <notAfter>2005 09 16 19 53 29</notAfter> 
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
<DigestValue>i1q2jwEDy0Sxc+ChxW9p4KCBynU=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>aXmExRkD4mZ9OdSlUcVUPIZ/r5v31Dq6IwU7Ox2/evd6maZeECVH4kGvGGez2VA5
lKhghRqgmAPsgEfZlZ3XwFxxo8tQuY6pi19OqwLV51R5klysX6fKkyK2JVoUG8Y3
7fACirNGZrZyf93X8sTvd02xN1DOTp7zt1afDsu3qGE=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>"""]

        ar1 = AuthorisationReq(proxyCert="A proxy cert",
                               aaWSDL="http://AttributeAuthority.wsdl",
                               extAttCertList=extAttCertList)
                            
        import pdb
        pdb.set_trace()
        ar2 = AuthorisationReq(xmlTxt=str(ar1))

                               
    def testAuthorisationResp1(self):

        try:
            attCert = \
"""<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=AttributeAuthority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>4</issuerSerialNumber>
        <validity>
            <notBefore>2006 04 03 09 09 26</notBefore>
            <notAfter>2006 04 03 17 08 25</notAfter>
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
<DigestValue>As4JwG1ABH5sA0vO7cOvGJK/PgQ=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>ECtPnRoQJFmWi91xaksaRxhrEweCdEc0+LOkdDlhCzfjRy8QxNogvc3spRKEn817
GVa3YLNLE3/UUZAxa4o+F4nI5WkGDFpnVyhfgA7dhhDL3khL1WKumGA303bqn0Ti
oK+T+rZ23VjFLtrvQjkwbh8gzyAgIFQL29ifIlu3hLk=</SignatureValue>
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
                           
            extAttCertList = [\
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 16 11 53 36</notBefore> 
        <notAfter>2005 09 16 19 53 29</notAfter> 
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
<DigestValue>i1q2jwEDy0Sxc+ChxW9p4KCBynU=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>aXmExRkD4mZ9OdSlUcVUPIZ/r5v31Dq6IwU7Ox2/evd6maZeECVH4kGvGGez2VA5
lKhghRqgmAPsgEfZlZ3XwFxxo8tQuY6pi19OqwLV51R5klysX6fKkyK2JVoUG8Y3
7fACirNGZrZyf93X8sTvd02xN1DOTp7zt1afDsu3qGE=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>""",
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 29 15 45 49</notBefore> 
        <notAfter>2005 09 29 23 45 49</notAfter> 
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
<DigestValue>/Kw9IbBQuQAdNYAgvp2m01l663k=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>Q7lhq/jt+m2trRPyWrZ6BQcIibXrstVS/xKTAhR4puv7kVngIm64r45MJ2GQpQan
QaVdVuOl8QPX8ila0j8sIz47FtriRWZ8fCssFYWR/7n3AKjNd22ChAshxHfZCJY4
fzJSXgEN+FN0ArOWT49FbhDVf7LEGO+MR+TP+ZKt6uY=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>""",
"""<?xml version="1.0"?>
<attributeCertificate>
    <acInfo>
        <version>1.0</version>
        <holder>/CN=pjkersha/O=NDG/OU=BADC</holder>
        <issuer>/CN=Attribute Authority/O=NDG/OU=BADC</issuer>
        <issuerName>BADC</issuerName>
        <issuerSerialNumber>6578</issuerSerialNumber> 
    <validity>
          <notBefore>2005 09 16 10 19 32</notBefore> 
        <notAfter>2005 09 16 18 19 14</notAfter> 
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
<DigestValue>tvftcf7fevu4PQqK2PhGFVzZlFo=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>cga7gcRSeKkI8+k5HiRdfxDz0wRA741lRaI0FCZ0e7rJH3IwxEv6C3fNB0a8Slgv
R2/1b+xCHtNX0jaMLDnAv/AvtC8DfcV8yiDZOAQ/qXDkASB2OHDo6qM+Zlkf97U+
dbjIuZ6bgXa2c9OlT9PUiCcDZt6uLmiu//28ZnFy7Pw=</SignatureValue>
<KeyInfo>
<X509Data>



<X509Certificate>MIICKDCCAZGgAwIBAgICGbIwDQYJKoZIhvcNAQEEBQAwYTEMMAoGA1UEChMDTkRH
MQ0wCwYDVQQLEwRCQURDMScwJQYDVQQLFB5uZGdwdXJzZWNhQGZvZWhuLmJhZGMu
cmwuYWMudWsxGTAXBgNVBAMTEEdsb2J1cyBTaW1wbGUgQ0EwHhcNMDUwODExMTQ1
NjM4WhcNMDYwODExMTQ1NjM4WjA7MQwwCgYDVQQKEwNOREcxDTALBgNVBAsTBEJB
REMxHDAaBgNVBAMTE0F0dHJpYnV0ZSBBdXRob3JpdHkwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALgmuDF/jKxKlCMqhF835Yge6rHxZFLby9BbXGsa2pa/1BAY
xJUiou8sIXO7yaWaRP7M9FwW64Vdk+HQI5zluG2Gtx4MgKYElUDCgPYXsvAXg0QG
bo0KSPr+X489j07HegXGjekNejLwwvB7qTSqxHjAaKAKL7vBfWf5mn0mlIwbAgMB
AAGjFTATMBEGCWCGSAGG+EIBAQQEAwIE8DANBgkqhkiG9w0BAQQFAAOBgQAmmqnd
rj6mgbaruLepn5pyh8sQ+Qd7fwotW00rEBRYzJNUUObmIry5ZM5zuVMcaPSY57qY
vWqnavydIPdu6N97/Tf/RLk8crLVOrqj2Mo0bwgnEnjmrQicIDsWj6bFNsX1kr6V
MtUg6T1zo/Yz1aYgGcW4A/ws5tmcEHS0PUGIGA==</X509Certificate>
<X509SubjectName>CN=Attribute Authority,OU=BADC,O=NDG</X509SubjectName>
<X509IssuerSerial>
<X509IssuerName>CN=Globus Simple CA,OU=ndgpurseca@foehn.badc.rl.ac.uk,OU=BADC,O=NDG</X509IssuerName>
<X509SerialNumber>6578</X509SerialNumber>
</X509IssuerSerial>
</X509Data>
</KeyInfo>
</Signature></attributeCertificate>"""]

            import pdb
            pdb.set_trace()                          
    
            ar1 = AuthorisationResp(attCert=attCert,
                            extAttCertList=extAttCertList,
                            statCode=AuthorisationResp.accessDenied,
                            errMsg="User is not registered at data centre")
        
            ar2 = AuthorisationResp(xmlTxt=str(ar1))
            
        except Exception, e:
            self.fail(str(e))
                                
class sessionMgrIOtestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(sessionMgrIOtestCase,
                  (
                    "testConnectReq1",
                    "testConnectReq2",
                    "testConnectResp1",
                    "testConnectResp2",
                    "testAuthorisationReq1",
                    "testAuthorisationResp1"
                  ))
        unittest.TestSuite.__init__(self, map)
                                        
if __name__ == "__main__":
    unittest.main()