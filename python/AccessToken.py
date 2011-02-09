#Copyright (C) 2004 CCLRC & NERC
#    This software may be distributed under the terms of the 
#    Q Public License, version 1.0 or later
#
# Version 0.4 BNL November 30, 2004
#
# Note that the signature handling needs to be setup with an external
# instance of SimpleSig (or whatever), passed into this as
# the SignatureHandler object ...
#
from X500DN import X500DN
import libxml2
import StringIO
from UserDict import UserDict

class DummyHandler:
  ''' Used for testing without "real" signature tooling '''
  def __init__(self):
    pass
  def sign(self,doc):
    pass
  def check(self,doc):
    return 1

class AccessToken(UserDict):
  ''' Handle an NDG token '''

  def __init__(self,holder=None,issuer=None,dpat=None,
               SignatureHandler=None):
    UserDict.__init__(self)
    self['holder']=X500DN()
    self['issuer']=X500DN()
    self['signatureAlgorithm']=''
    self['attributes']=[]
    self['notBefore']=(0,0,0,0,0)
    self['notAfter']=(0,0,0,0,0)
    if dpat!=None:
      self.xmlset(dpat)
    else:
      self.set(holder,issuer)
    self['issuerName']=''
    self['issuerSerialNumber']=0
    if SignatureHandler is None:
      self.handler=DummyHandler()
    else:
      self.handler=SignatureHandler

  def set(self,holder=None,issuer=None):
    if holder is not None: self['holder'].update(holder)
    if issuer is not None: self['issuer'].update(issuer)

  def sign(self):
    myxml=self.xml()
    if self.handler.check(myxml):
      # already signed, do nothing
      pass
    else:
      # sign it and re-initialise
      myxml=self.handler.sign(myxml)
      self.xmlset(myxml)
      return myxml
    
  def checkSig(self):
    myxml=self.xml()
    return SignatureHandler.check(myxml)
    
  def add(self,args):
    self['attributes'].extend(args)

  def show(self):
    lines='___________________'
    print lines,'  Holder  ',lines
    for i in self['holder'].keys():
      if self['holder'][i] !='': print i,self['holder'][i]
    print lines,'  Issuer  ', lines
    for i in self['issuer'].keys():
      if self['issuer'][i] !='': print i,self['issuer'][i]
    print lines,'  Validity  ',lines[:-2]
    print 'Valid from :', self['notBefore'],' to ',self['notAfter']

  def xmlset(self,dpat):
    ''' This piece of code parses an XML CLRC Data Portal Access Token
    and sets this Access Token accordingly. It is assumed that the
    dpat is passed a string argument '''
    #note, choosing to use libxml2 here since we use it for the signatures
    #anyway ... I might have chosen another parser otherwise.
    doc=libxml2.parseDoc(dpat)
    #check we can understand this certificate
    #start by loading up a dictionary of the elements ...
    ctxt=doc.xpathNewContext()
    a=ctxt.xpathEval("/attributeCertificate/acInfo")[0]
    # nb, this next statement produces a few nested elements that
    # we can't use simply, but the bottom level ones (which
    # are the ones we want) are done very quickly ...
    token=dict([(i.name,i.content) for i in a])
    #ok, now go ahead and load up ...
    #print token.keys()
    if token['version'] != '1.0':
      raise 'Access Token Version not recognised'
    for i in ['version','signatureAlgorithm',
              'notBefore','notAfter']: self[i]=token[i]
    self.set(holder=token['holder'],issuer=token['issuer'])    
    #the C things need to be explicitly dereferenced I think
    doc.freeDoc()
    ctxt.xpathFreeContext()

  def xml(self):
    ''' This piece of code write a CCLRC Data Portal Access Token encoded in
    XML '''
    s='<attributeCertificate><acInfo><version>1.0 </version>'
    for i in ('holder','issuer'):
      s+='<'+i+'>'+self[i].serialise()+'</'+i+'>'
    s+=self.xmlkey('issuerName','issuerSerialNumber','signatureAlgorithm')
    s+='<validity>'+self.xmlkey('notBefore','notAfter')+'</validity>'
    s+='<attributes>'
    for i in self['attributes']:s+=i+','
    s=s[:-1]+'</attributes></acinfo>'
    s+='SignatureGoesHere'  # we'll do this properly when we know how
    s+='</attributeCertificate>'
    return s
    pass

  def xmlkey(self,*arglist):
    s=''
    for i in arglist:
      s+='%s%s%s%s%s%s%s'%('<',str(i),'>',str(self[i]),'</',str(i),'>')
    return s

if __name__=='__main__':
  print 'demonstrate use of Access Token'
  holder=X500DN({'CN':'Bryan Lawrence','O':'NERC DataGrid','C':'UK'})
  issuer=X500DN({'CN':'NDG Data Provider','O':'BADC','C':'UK'})
  at=AccessToken(holder=holder,issuer=issuer)
  at.show()
  #
  f=open('../ws.cred','r')
  dpat=f.read()
  at=AccessToken(dpat=dpat)
  y=at.xml()
  print y
