from elementtree import ElementTree, ElementC14N
from StringIO import StringIO

soapNSURI = 'http://schemas.xmlsoap.org/soap/envelope/'
env = ElementTree.Element("{%s}SOAP-ENV:Envelope" % soapNSURI)
hdr = ElementTree.Element("{%s}SOAP-ENV:Header" % soapNSURI)
env.append(hdr)
root = ElementTree.ElementTree(element=env)
f = StringIO()
ElementC14N.write(root, f)
print f.getvalue()