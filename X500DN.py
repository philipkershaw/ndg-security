#Copyright (C) 2004 CCLRC & NERC
#    This software may be distributed under the terms of the 
#    Q Public License, version 1.0 or later
#
# Version 0.1 BNL November 12, 2004
#
from UserDict import UserDict

class X500DN(UserDict):
  ''' An X500 Distinguished Name from RFC2253 (supplemented with
  Email address) expressed as a python dictionary '''
  def __init__(self,argdict=None):
    self.longNames={'CN':'commonName',
                   'OU':'OrganisationalUnitName',
                   'O':'Organisation',
                   'C':'CountryName',
                   'EMAIL':'Email Address',
                   'L':'localityName',
                   'ST':'stateOrProvinceName',
                   'STREET':'streetAddress',
                   'UID':'userid'}
    UserDict.__init__(self,self.longNames)
 
    self._clear()
    if argdict is not None:
      for i in argdict: self.data[i]=argdict[i]

  def _clear(self):
    for i in self.keys(): self.data[i]=''

  def __delitem__(self,key):
    raise 'Keys cannot be deleted from the X500DN '

  def __setitem__(self,key,item):
    if key not in self.data.keys():
      raise 'Key '+key+' not known in X500DN '
    self.data[key]=item

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

  def deserialise(self,s):
    list=s.split(',')
    self._clear()
    for item in list:
      key,value=item.split('=')
      self.data[key]=value

if __name__=='__main__':
  print 'Demonstrating the use of X500DN'
  y=X500DN()
  print y
  print y.longNames
  print y.keys()
  
  y['CN']='Bryan'

  print 'show the serialisation'
  print y.serialise()
  y.deserialise('DN = Another Bryan, C = Another place')
  print y

  y['ABC']='bnl' #should break
  
