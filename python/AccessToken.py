#Copyright (C) 2004 CCLRC & NERC
#    This software may be distributed under the terms of the 
#    Q Public License, version 1.0 or later
#
# Version 0.1 BNL November 12, 2004

from X500DN import X500DN

class Validity:
  def __init__(self,start=(0,0,0,0,0),finish=(0,0,0,0,0)):
    self.start=start
    self.finish=finish
  def checkvalid(now=None):
    valid=0
    if now is None:
      pass
      #really what we should do is get the current time
    else:
      valid=1
      #for i in range(5):
      #  if now[i]<self.start[i] or now[i]>self.finish[i]:valid=0
    return valid

class AccessToken(Validity):
  ''' Handle an NDG token
      Version 0.1, BNL, November 12, 2004 '''

  def __init__(self,holder=None,issuer=None,dpat=None):
    self.holder=X500DN()
    self.issuer=X500DN()
    self.signature=''
    self.attributes=[]
    Validity.__init__(self)
    if dpat!=None:
      self.xmlset(dpat)
    else:
      self.set(holder,issuer)

  def set(self,holder=None,issuer=None):
    if holder is not None: self.holder.update(holder)
    if issuer is not None: self.issuer.update(issuer)


  def sign(self):
    pass    # for now 

  def checkSig(self):
    return 1  #for now
    
  def add(self,args):
    self.attributes.extend(args)

  def show(self):
    lines='___________________'
    print lines,'  Holder  ',lines
    for i in self.holder.keys():
      if self.holder[i] !='': print i,self.holder[i]
    print lines,'  Issuer  ', lines
    for i in self.issuer.keys():
      if self.issuer[i] !='': print i,self.issuer[i]
    print lines,'  Validity  ',lines[:-2]
    print 'Valid from :', self.start,' to ',self.finish

  def xmlset(self,dpat):
    ''' This piece of code parses an XML CLRC Data Portal Access Token
    and sets this Access Token accordingly'''
    pass

  def xmlout(self):
    ''' This piece of code write a CCLRC Data Portal Access Token encoded in
    XML '''
    dpat=''
    return dpat
    pass

if __name__=='__main__':
  print 'demonstrate use of Access Token'
  holder=X500DN({'DN':'Bryan Lawrence','O':'NERC DataGrid','C':'UK'})
  issuer=X500DN({'DN':'NDG Data Provider','O':'BADC','C':'UK'})
  at=AccessToken(holder=holder,issuer=issuer)
  at.show()
