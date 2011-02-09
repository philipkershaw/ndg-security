#!/usr/bin/env python
import re
from elementtree import ElementTree, ElementC14N
from StringIO import StringIO

    
soapNSURI = 'http://schemas.xmlsoap.org/soap/envelope/'

envElem = ElementTree.Element("{%s}Envelope" % soapNSURI) 
envElem.set("xmlns:SOAP-ENV", soapNSURI)

hdrElem = ElementTree.Element("{%s}Header" % soapNSURI)
envElem.set("xmlns:SOAP-ENV", soapNSURI)
envElem.append(hdrElem)

bodyElem = ElementTree.Element("{%s}Body" % soapNSURI)
envElem.set("xmlns:SOAP-ENV", soapNSURI)
envElem.append(bodyElem)
wsuNS='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
envElem.set('xmlns:wsu', wsuNS)
envElem.set('URI', "http://blah")
bodyElem.set('{%s}Id' % wsuNS, '#body')

ndgSecNS = "urn:ndg:security:test:wssecurity"
echoElem = ElementTree.Element("{%s}Echo" % ndgSecNS)
echoElem.set('xmlns:ns0', ndgSecNS)
bodyElem.append(echoElem)

echoInElem = ElementTree.Element("{%s}EchoIn" % ndgSecNS)
echoInElem.text = "hello"
echoElem.append(echoInElem)

print "Calling Inclusive C14N  ..."
f = StringIO()
ElementC14N.write(ElementC14N.build_scoped_tree(envElem), f)
print f.getvalue()

print "Calling Exclusive C14N for body element ..."
g = StringIO()
ElementC14N.write(ElementC14N.build_scoped_tree(envElem), g, exclusive=True,
                  subset=bodyElem)
c14n = g.getvalue()
print c14n



