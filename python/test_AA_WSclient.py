#
#
# This is a test client for the NDG Attribute Authority 
#
from ZSI import *
fp=open('client-debug.out','a')
b=Binding(url='http://localhost:4999',tracefile=fp)
try:
    a=b.AAWS('getTrustedHosts','nerc')
except FaultException,e:
    print e
print a
fp.close()
