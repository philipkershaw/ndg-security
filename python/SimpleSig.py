# Copyright (C) 2004 CCLRC & NERC
#
#    Note that this version is heavily influenced by the example
#    code which comes with pyxmlsec, which is copyright to
#    Valery Febvre <vfebvre@easter-eggs.com>, and distributed under
#    the GPL.
#
# Version 0.2 BNL November 30, 2004
#
# Note that there are problems with instantiating and releasing multiple
# instances in one stack, this can be avoided by NOT releasing earlier
# instances ... as shown in the commented main below. I've pointed this
# problem out to the mailing list ...
#

import libxml2
import xmlsec
import os
import StringIO

class  SimpleSig:
  
  ''' provides signing of xml documents with minimum number of arguments '''
  
  def __init__(self,myprivatekey,myx509cert,rootcert):

    ''' On initialisation, provide the provide key, public certificate needed
    sign documents, and the root certificate needed to validate the x509
    certificates which are used to sign documents '''
    
    self.myprivatekey=myprivatekey
    self.myx509cert=myx509cert
    self.rootcert=rootcert

    if (not os.access(self.myprivatekey, os.R_OK) or
        not os.access(self.myx509cert,os.R_OK) or
        not os.access(self.rootcert,os.R_OK) ):
        self.release()
        raise "Either key or cert not found or readable"

    #initialise xmlsec
    if xmlsec.init() < 0: raise xmlsec_failure
    
    # Init crypto library
    if xmlsec.cryptoAppInit(None) < 0: raise xmlsec_failure

    # Init xmlsec-crypto library
    if xmlsec.cryptoInit() < 0: raise xmlsec_failure

    # Create keys manager and load trusted certificates
    self._load_trusted_certs([rootcert], 1)

  def sign(self,xmldoc):

    doc=libxml2.parseDoc(xmldoc)
    self.doc=doc
    
    #create signature template
    signNode=xmlsec.TmplSignature(doc, xmlsec.transformExclC14NId(),
                                    xmlsec.transformRsaSha1Id(), None)

    #if signNode is None: self.xmlsec_failure
    # add <dsig:Signature> element
    doc.getRootElement().addChild(signNode)
    # add reference
    #addReference(self, digestMethodId, id=None, uri=None, type=None) 

    refNode = signNode.addReference(xmlsec.transformSha1Id(),
                                    None,'', None)
    if refNode is None: raise self.xmlsec_failure()
    # add enveloped transform
    if refNode.addTransform(xmlsec.transformEnvelopedId()) is None:
      self.xmlsec_failure()
    # Add <dsig:KeyInfo/> and <dsig:X509Data/>
    keyInfoNode = signNode.ensureKeyInfo(None)
    if keyInfoNode is None: self.xmlsec_failure()
    if keyInfoNode.addX509Data() is None: self.xmlsec_failure()

    # Create Signature context
    dsig_ctx = xmlsec.DSigCtx()
    self.context=dsig_ctx
    
    if dsig_ctx is None:
        print "Error: failed to create signature context"
        return self.xmlsec_failure()

    # Load private key, assuming that there is not password
    key = xmlsec.cryptoAppKeyLoad(self.myprivatekey, xmlsec.KeyDataFormatPem,
                                  None, None, None)
    if key is None:
        print "Error: failed to load private pem key from \"%s\"" % key_file
        return self.xmlsec_failure()
      
    dsig_ctx.signKey = key

    # Load certificate and add to the key
    # actually should have this preloaded in the init ...
    if xmlsec.cryptoAppKeyCertLoad(key, self.myx509cert,
                                   xmlsec.KeyDataFormatPem) < 0:
        print "Error: failed to load pem certificate \"%s\"" % cert_file
        self.xmlsec_failure()
        
    # Set key name to the file name, this is just an example!
    if key.setName(self.myprivatekey) < 0:
        print "Error: failed to set key name for key from \"%s\"" % key_file
        return self.xmlsec_failure()

    # Sign the template
    if dsig_ctx.sign(signNode) < 0:
        print "Error: signature failed"
        return self.xmlsec_failure()

    ans=doc.serialize()
    doc.freeDoc()
    return ans

  def xmlsec_failure(self,value=None,step=0):

    print "xmlsec failure"
    
    raise "Problems with xmlsec"

  def release(self):
    
    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    # libxml2.cleanupParser()
    # dont we get this from the freedoc alone?

  def check(self,xmldoc):

    doc = libxml2.parseDoc(xmldoc)
    if doc is None or doc.getRootElement() is None:
      self._cleanup(doc)
      print 'Unable to parse document'
      return 0
       
    # Find start node
    node = xmlsec.findNode(doc.getRootElement(),
                           xmlsec.NodeSignature, xmlsec.DSigNs)
    if node is None:
      print "Error: start node not found in \"%s\"", xml_file
      self._cleanup(doc)
      return 0
      
    # Create signature context
    dsig_ctx = xmlsec.DSigCtx(self.mngr)
    if dsig_ctx is None:
        print "Error: failed to create signature context"
        self._cleanup(doc)
        return 0

    # Verify signature
    if dsig_ctx.verify(node) < 0:
        print "Error: signature verify"
        self._cleanup(doc, dsig_ctx)
        return 0

    # Print verification result to stdout
    if dsig_ctx.status == xmlsec.DSigStatusSucceeded:#
        self._cleanup(doc,dsig_ctx)
        return 1  # valid
    else:
        self._cleanup(doc,dsig_ctx)
        return 0  # invalid

  def _cleanup(self,doc=None, dsig_ctx=None, res=-1):
    if dsig_ctx is not None:
      dsig_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    
  def _load_trusted_certs(self, files, n):

    # Create and initialize keys manager, we use a simple list based
    # keys manager, implement your own KeysStore klass if you need
    # something more sophisticated
    
    mngr = xmlsec.KeysMngr()
    if mngr is None:
        print "Error: failed to create keys manager."
        return None
    if xmlsec.cryptoAppDefaultKeysMngrInit(mngr) < 0:
        print "Error: failed to initialize keys manager."
        mngr.destroy()
        return None
    for file in files:
      if not os.access(file,os.R_OK):
        mngr.destroy()
        return None
      # Load trusted cert
      if mngr.certLoad(file, xmlsec.KeyDataFormatPem,
                       xmlsec.KeyDataTypeTrusted) < 0:
        print "Error: failed to load pem certificate from \"%s\"", file
        mngr.destroy()
        return None
    self.mngr=mngr
  

if __name__=="__main__":

  doc='''<?xml version="1.0" encoding="UTF-8"?>
  <Envelope>
  <Data>
        Hello, World!
  </Data>
  </Envelope>
  '''
  key='rsakey.pem'
  cert='rsacert.pem'
  rootcert='rootcert.pem'

  x=SimpleSig(key,cert,rootcert)
  
  y=x.sign(doc)
  r=x.check(y)

  print 'Validity 1 is ',r

  # logically at this point we could do the following
  #
  #  x.release()
  #
  # but if we then carry on with another instance, we end
  # up with an infinite loop at the termination, this is simply
  # avoided (hopefuly without memory leaks) by only doing one release.
  # I wish I understood what was going on here ...
  # This seems only to be a problem with glibc 3.2.3 (and greater?)
  #

  z=SimpleSig(key,cert,rootcert)
  y=z.sign(doc)
  r=z.check(y)
  
  print 'Validity 2 is ',r

  z.release()


