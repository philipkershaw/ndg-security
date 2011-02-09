#Copyright (C) 2004 CCLRC & NERC
#    This software may be distributed under the terms of the 
#    Q Public License, version 1.0 or later
#
# Version 0.3 BNL November 30, 2004
#
from UserDict import UserDict

class X500DN(UserDict):
  ''' An X500 Distinguished Name from RFC2253 (supplemented with
  Email address) expressed as a python dictionary '''
  def __init__(self,argdict=None,x509m2=None):
    self.longNames={'CN':'commonName',
                   'OU':'OrganisationalUnitName',
                   'O':'Organisation',
                   'C':'CountryName',
                   'emailAddress':'Email Address',
                   'L':'localityName',
                   'ST':'stateOrProvinceName',
                   'STREET':'streetAddress',
                   'DC':'domainComponent',
                   'UID':'userid'}
    UserDict.__init__(self,self.longNames)
    self._clear()
    if argdict is not None:
      self.update(argdict)
    if x509m2 is not None:
      # the argument is an x509 certificate in m2crypto format
      self.data['CN']=x509m2.CN
      self.data['L']=x509m2.L
      self.data['O']=x509m2.O
      self.data['OU']=x509m2.OU
      self.data['EMAILADDRESS']=x509m2.Email
      #self.data['DC']=x509m2.DC
        
  def _clear(self):
    for i in self.keys(): self.data[i]=''

  def __delitem__(self,key):
    raise 'Keys cannot be deleted from the X500DN '

  def __setitem__(self,key,item):
    if key not in self.longNames.keys():
      raise 'Key '+key+' not known in X500DN '
    self.data[key]=item

  def update(self,dict):
    #check and see if it is a dict, if not, deserialise
    if dict.__class__() == '':
      self.deserialise(dict)
    else:
      for k,i in dict.items():
        k=k.join(k.split())
        self.__setitem__(k,i)

  def serialise(self):
    ''' Return X500 string '''
    keys=self.data.keys()
    keys.sort()
    s=''
    for i in keys:
      if self.data[i]!='':
        s+=i+' = '+self.data[i]+','
    if len(s)!=0:s=s[:-1] # trim last comma
    return s

  def deserialise(self,s,m2crypto=0):
    ''' Handle an X500DN as a string and parse into the dictionary, noting
    that folks handle this in a variety of ways, and  this  currently only
    works with comma separated '''
    list=s.split(',')
    self._clear()
    print list
    argdict=dict([ item.split('=') for item in list])
    self.update(argdict)
    #for item in list:
    # key,value=item.split('=')
    # self.data[key]=value

if __name__=='__main__':
  print 'Demonstrating the use of X500DN'
  y=X500DN()
  print y
  print y.longNames
  print y.keys()
  
  y['CN']='Bryan'

  print 'show the serialisation'
  print y.serialise()
  print 'show use of deserialising for instantiation'
  y=X500DN('CN = Another Bryan, C = Another place')
  print y
  print 'Next statement should break with a key error!'
  y=X500DN('ABC=bnl')
  
