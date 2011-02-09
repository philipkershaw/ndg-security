#!/usr/bin/env python
"""NDG ElementTreeC14n class unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/01/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import sys
import getpass
import traceback

from difflib import unified_diff

from StringIO import StringIO

from elementtree import ElementC14N as ETC14N
from elementtree import ElementTree as ET

# Minidom based Canonicalization from ZSI for comparison
from ZSI.wstools.c14n import Canonicalize

from xml.xpath.Context import Context
from xml import xpath
from xml.dom.ext.reader import PyExpat

xpdVars = os.path.expandvars
jnPath = os.path.join

class ElementTreeC14nTestCase(unittest.TestCase):
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()          

    def assertEqual(self, a, b):
        '''Override default to get something easy to read than super class
        behaviour'''
        if a != b:
            diffGen = unified_diff(a.split('\n'), b.split('\n'))
            raise AssertionError('\n'+'\n'.join(diffGen))
        
    def test01UTF8DocEncoding(self):
        
        # http://www.w3.org/TR/xml-c14n#Example-UTF8
        xml = '<?xml version="1.0" encoding="ISO-8859-1"?><doc>&#169;</doc>'
        elem = ET.fromstring(xml)
        f = StringIO()
        ETC14N.write(elem, f)
        c14n = f.getvalue()
        #self.assertEqual(c14n, '<doc>#xC2#xA9</doc>')
        self.assertEqual(c14n, '<doc>\xC2\xA9</doc>')

    def test01aPIsCommentsAndOutsideOfDocElem(self):
        # http://www.w3.org/TR/xml-c14n#Example-OutsideDoc - PIs, Comments, and
        # Outside of Document Element 
        xml = \
'''<?xml version="1.0"?>

<?xml-stylesheet   href="doc.xsl"
   type="text/xsl"   ?>

<!DOCTYPE doc SYSTEM "doc.dtd">

<doc>Hello, world!<!-- Comment 1 --></doc>

<?pi-without-data     ?>

<!-- Comment 2 -->

<!-- Comment 3 -->'''

        exptdC14n = \
'''<?xml-stylesheet href="doc.xsl"
   type="text/xsl"   ?>
<doc>Hello, world!</doc>
<?pi-without-data?>'''

        elem = ET.fromstring(xml)
        f = StringIO()
        ETC14N.write(elem, f)
        c14n = f.getvalue()
        self.assertEqual(c14n, exptdC14n)

   
    def test02NormalizeLineBreaks(self):
        xml = '<?xml version="1.0" encoding="UTF-8"?>\r\n<a/>\r\n'
        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        self.failIf('\r' in c14n, "Carriage return \r char found in c14n")

    
    def test03NormalizedAttrVals(self):
        pass

   
    def test04CharAndParsedEntityRefsReplaced(self):
        xml = '''<!DOCTYPE doc [
<!ATTLIST doc attrExtEnt ENTITY #IMPLIED>
<!ENTITY ent1 "Hello">
<!ENTITY ent2 SYSTEM "world.txt">
<!ENTITY entExt SYSTEM "earth.gif" NDATA gif>
<!NOTATION gif SYSTEM "viewgif.exe">
]>
<doc attrExtEnt="entExt">
   &ent1;, &ent2;!
</doc>

<!-- Let world.txt contain "world" (excluding the quotes) -->'''

        exptdC14n = '''<doc attrExtEnt="entExt">
   Hello, world!
</doc>'''
        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        self.assertEqual(c14n, exptdC14n)
        
    
    def test05CDATASectionsReplaced(self):
        xml = \
"""<?xml version="1.0" encoding="UTF-8"?>
<script>
<![CDATA[
function matchwo(a,b)
{
if (a < b && a > 0) then
   {
   print("Match");
   return 1;
   }
else
   {
   print('Different');
   return 0;
   }
}
]]>
</script>
"""
        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        
        self.failIf('CDATA' in c14n, "CDATA not removed, c14n = %s" % c14n)
        self.failUnless('&lt;' in c14n,
                        "Less than not converted, c14n = %s" % c14n)
        self.failUnless('&gt;' in c14n, 
                        "Greater than not converted, c14n = %s" % c14n)
        self.failUnless('&amp;' in c14n, 
                        "Ampersand not converted, c14n = %s" % c14n)

        # Test for double quotes / apostrophes?
        
    
    def test06XMLDeclAndDTDRemoved(self):
        xmlDecl = '<?xml version="1.0" encoding="UTF-8"?>'
        dtd = \
"""<!DOCTYPE note [
  <!ELEMENT note (to,from,heading,body)>
  <!ELEMENT to      (#PCDATA)>
  <!ELEMENT from    (#PCDATA)>
  <!ELEMENT heading (#PCDATA)>
  <!ELEMENT body    (#PCDATA)>
]>
"""
        xml = \
"""%s
%s<a/>""" % (xmlDecl, dtd)

        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        self.failIf('<?xml version="1.0" encoding="UTF-8"?>' in c14n, 
                    "XML Declaration not removed")
        self.failIf(dtd in c14n, "DTD not removed")

   
    def test07EmptyElemsConvertedStartEndPairs(self):
        elem = ET.fromstring('<?xml version="1.0" encoding="UTF-8"?><a/>')
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        self.failUnless(c14n == '<a></a>', "C14N = %s" % c14n)

          
    def test08WhitespaceNormalized(self):
        # ...outside the document element and within start and end tags
        dat = \
'''        1 2 
  3'''
  
        xml = \
'''<?xml version="1.0" encoding="UTF-8"?>
<doc xmlns="http://example.com/default">
  <a
     a2="2"   a1="1"
  >%s</a>
</doc>

''' % dat

        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        
        self.failUnless('a1="1" a2="2"' in c14n, 
                        "Expecting single space between attributes")
        self.failUnless(dat in c14n, 
                        "Expecting element content to be preserved")
        
        sub = c14n[c14n.find('<a'):c14n.find('>')]
        self.failIf('\n' in sub, 
                    "Expecting removal of line breaks for 'a' element")
     
     
    def test09WhitespaceInCharContentRetained(self):
        # http://www.w3.org/TR/xml-c14n#Example-WhitespaceInContent
        # Nb. excludes chars removed during line break normalization
        xml = \
'''<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>'''
        elem = ET.fromstring(xml)
        f = StringIO()
        ETC14N.write(elem, f)
        c14n = f.getvalue()
        
        # In this case the canonicalized form should be identical to the 
        # original
        self.assertEqual(c14n, xml)

        
    def test10AttrValDelimitersSet2DblQuotes(self):
        xml = \
"""<?xml version="1.0" encoding="UTF-8"?>
  <b y:a1='1' a3='"3"'
     xmlns:y='http://example.com/y' y:a2='2'/>
"""

        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        self.failIf("'" in c14n, 
                    "Expecting removal of apostrophes C14N = %s" % c14n)

    
    def test11SpecialCharsReplaced(self):
        # i.e. within attribute values and character content
        pass
        
        
    def test12SuperflousNSdeclsRemoved(self):
        extraNS = "http://example.com/default"
        xml = \
"""<?xml version="1.0" encoding="UTF-8"?>
<doc xmlns:x="http://example.com/x" xmlns="%s">
  <b y:a1='1' xmlns="%s" a3='"3"'
     xmlns:y='http://example.com/y' y:a2='2'/>
</doc>""" % (extraNS, extraNS)

        elem = ET.fromstring(xml)
        f = StringIO()
        ET.ElementTree(elem).write_c14n(f)
        c14n = f.getvalue()
        
        # Namespace should now only occur once...
        self.failUnless(c14n.find(extraNS) == c14n.rfind(extraNS), 
                    "Expecting removal of extra NS %s in output = %s" % \
                    (extraNS, c14n))
        
        
    def test13DefAttrsAdded2EachElem(self):
        # Ref. http://www.w3.org/TR/xml-c14n#Example-SETags
        xml = '''<!DOCTYPE doc [<!ATTLIST e9 attr CDATA "default">]>
<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>'''

        elem = ET.fromstring(xml)
        f = StringIO()
#        ET.ElementTree(elem).write_c14n(f)
        ETC14N.write(elem, f)
        c14n = f.getvalue()

        exptdC14n = '''<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org" attr="default"></e9>
         </e8>
      </e7>
   </e6>
</doc>'''
        self.assertEqual(c14n, exptdC14n)
        
    def test14DocumentSubsets(self):
        # Ref. http://www.w3.org/TR/xml-c14n#Example-DocSubsets
        xml = \
"""<!DOCTYPE doc [
<!ATTLIST e2 xml:space (default|preserve) 'preserve'>
<!ATTLIST e3 id ID #IMPLIED>
]>
<doc xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org">
   <e1>
      <e2 xmlns="">
         <e3 id="E3"/>
      </e2>
   </e1>
</doc>"""

#'''<!-- Evaluate with declaration xmlns:ietf="http://www.ietf.org" -->
        xpathExpr = \
'''
(//. | //@* | //namespace::*)
[
   self::ietf:e1 or (parent::ietf:e1 and not(self::text() or self::e2))
   or
   count(id("E3")|ancestor-or-self::node()) = count(ancestor-or-self::node())
]'''

        exptdC14n = \
'<e1 xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org"><e3 xmlns="" id="E3" xml:space="preserve"></e3></e1>'

        elem = ET.fromstring(xml)
        f = StringIO()
        subElem = elem.find(xpathExpr)
        ETC14N.write(elem, f, subset_element=subElem)
        c14n = f.getvalue()

    def test15CmpZSIc14n(self):
        elem = ETC14N.parse('./windows-ac.xml')
        ETC14N.write(elem, './et-c14n-ac.xml')
        
        from xml.dom.ext.reader import PyExpat
        reader = PyExpat.Reader()
        dom = reader.fromStream(open('./windows-ac.xml'))
        
        zsiC14n = Canonicalize(dom)
        etC14n = open('./et-c14n-ac.xml').read()
        open('./zsi-c14n-ac.xml', 'w').write(zsiC14n)
        
        etC14n = open('./et-c14n-ac.xml').read()

        self.failUnless(etC14n == zsiC14n, "ZSI C14N output differs")
        
    def test16Cmplxmlc14n(self):
        from StringIO import StringIO

        elem = ETC14N.parse('./windows-ac.xml')
        ETC14N.write(elem, './et-c14n-ac-2.xml')
        
        
        from lxml import etree as lxmlET
        
        lxmlElem = lxmlET.parse('./windows-ac.xml')
        lxmlETf = StringIO()
        lxmlElem.write_c14n(lxmlETf)
        open('./lxml-c14n-ac.xml', 'w').write(lxmlETf.getvalue())
        
        f1 = open('./et-c14n-ac-2.xml')
        etC14n = f1.read()
        f1.close()
        
        self.failUnless(etC14n == lxmlETf.getvalue(),
                        "lxml C14N output differs")
        
        
    def test17InclusiveC14nWithXPath(self):
        # Inclusive Canonicalization of portions of a SOAP message extracted 
        # using XPath
        
        inputFile = './soapGetAttCertResponse.xml'
        
        reader = PyExpat.Reader()
        dom = reader.fromStream(open(inputFile))
        processorNss = \
        {
            'wsu': \
"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        }
    
        ctxt = Context(dom, processorNss=processorNss)
        zsiRefNodes = xpath.Evaluate('//*[@wsu:Id]', 
                                  contextNode=dom, 
                                  context=ctxt)
        
        # ElementTree
        elem = ETC14N.parse(inputFile)
        
        # Extract nodes for signing
        etRefNodes = elem.findall('.//*[@wsu:Id]', namespaces=processorNss)
        
        for zsiRefNode, etRefNode in zip(zsiRefNodes, etRefNodes):
            # Get ref node and all it's children
            zsiRefC14n = Canonicalize(zsiRefNode)

#            print "_"*80
#            print "ZSI Inclusive C14N %s:\n" % zsiRefNode.nodeName
#            print zsiRefC14n
            open('soapGetAttCertResponse-%s-zsi-c14n.xml'%zsiRefNode.localName, 
                 'w').write(zsiRefC14n)
                 
            f = StringIO()
            ETC14N.write(elem, f, subset=etRefNode)
            etRefC14n = f.getvalue()
            
#            print "_"*80
#            print "ElementTree Inclusive C14N %s:\n" % etRefNode.tag
#            print etRefC14n
            open('soapGetAttCertResponse-%s-et-c14n.xml' % \
                 etRefNode.tag.split('}')[-1], 
                 'w').write(etRefC14n)
            self.assertEqual(zsiRefC14n, etRefC14n)
        
    def test18ExclC14nWithXPath(self):
        # Exclusive C14N applied to portions of a SOAP message by extracting
        # using XPath
        
        inputFile = './soapGetAttCertResponse.xml'

        reader = PyExpat.Reader()
        dom = reader.fromStream(open(inputFile))
        processorNss = \
        {
            'wsu': \
"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        }
    
        ctxt = Context(dom, processorNss=processorNss)
        zsiRefNodes = xpath.Evaluate('//*[@wsu:Id]', 
                                  contextNode=dom, 
                                  context=ctxt)
        # ElementTree
        elem = ETC14N.parse(inputFile)
        
        # Extract nodes for signing
        etRefNodes = elem.findall('.//*[@wsu:Id]', namespaces=processorNss)
        
        for zsiRefNode, etRefNode in zip(zsiRefNodes, etRefNodes):
            # Get ref node and all it's children
            refSubsetList = getChildNodes(zsiRefNode)
            zsiRefC14n = Canonicalize(dom, None, subset=refSubsetList,
                                   unsuppressedPrefixes=[])

#            print "_"*80
#            print "ZSI Exclusive C14N %s:\n" % zsiRefNode.nodeName
#            print zsiRefC14n
            open('soapGetAttCertResponse-%s-exclC14n.xml'%zsiRefNode.localName, 
                 'w').write(zsiRefC14n)
        
            # ElementTree equivalent     
            f = StringIO()
            ETC14N.write(elem, f, etRefNode, exclusive=True)
            etRefC14n = f.getvalue()
            
#            print "_"*80
#            print "ElementTree Exclusive C14N %s:\n" % etRefNode.tag
#            print etRefC14n
            open('soapGetAttCertResponse-%s-et-exclC14n.xml' % \
                 etRefNode.tag.split('}')[-1], 
                 'w').write(etRefC14n)
        
            self.assertEqual(zsiRefC14n, etRefC14n)
        
    def test19ExclC14nWithXPathAndInclusiveNSPfx(self):
        # Exclusive C14N applied to portions of a SOAP message by extracting
        # using XPath
        inputFile = './soapGetAttCertResponse.xml'
        
        from xml.xpath.Context import Context
        from xml import xpath
        from xml.dom.ext.reader import PyExpat
        reader = PyExpat.Reader()
        dom = reader.fromStream(open(inputFile))
        processorNss = \
        {
            'wsu': \
"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        }
    
        ctxt = Context(dom, processorNss=processorNss)
        zsiRefNodes = xpath.Evaluate('//*[@wsu:Id]', 
                                  contextNode=dom, 
                                  context=ctxt)

        # ElementTree
        elem = ETC14N.parse(inputFile)
        
        # Extract nodes for signing
        etRefNodes = elem.findall('.//*[@wsu:Id]', namespaces=processorNss)
        
        nsPfx = ['SOAP-ENV', 'ds']
        for zsiRefNode, etRefNode in zip(zsiRefNodes, etRefNodes):
            # Get ref node and all it's children
            refSubsetList = getChildNodes(zsiRefNode)
            zsiRefC14n = Canonicalize(dom, None, subset=refSubsetList,
                                   unsuppressedPrefixes=nsPfx)

#            print "_"*80
#            print "Exclusive C14N with Prefixes %s:\n" % zsiRefNode.nodeName
#            print zsiRefC14n
            open('soapGetAttCertResponse-%s-exclC14nWithInclPrefixes.xml' % \
                 zsiRefNode.localName, 
                 'w').write(zsiRefC14n)
        
            # ElementTree equivalent     
            f = StringIO()
            ETC14N.write(elem, f, subset=etRefNode, exclusive=True,
                         inclusive_namespaces=nsPfx)
            etRefC14n = f.getvalue()
            
#            print "_"*80
#            print "ElementTree Exclusive C14N %s:\n" % etRefNode.tag
#            print etRefC14n
            open('soapGetAttCertResponse-%s-et-exclC14n.xml' % \
                 etRefNode.tag.split('}')[-1], 
                 'w').write(etRefC14n)

            self.assertEqual(zsiRefC14n, etRefC14n)
      

def getChildNodes(node, nodeList=None):
    if nodeList is None:
        nodeList = [node] 
    return _getChildNodes(node, nodeList=nodeList)
           
def _getChildNodes(node, nodeList=None):

    if node.attributes is not None:
        nodeList += node.attributes.values() 
    nodeList += node.childNodes
    for childNode in node.childNodes:
        _getChildNodes(childNode, nodeList)
    return nodeList

if __name__ == "__main__":
    unittest.main()

