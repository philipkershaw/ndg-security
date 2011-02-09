#Copyright (C) 2004 CCLRC & NERC
#    This software may be distributed under the terms of the 
#    Q Public License, version 1.0 or later
#
# Version 0.1 BNL November 12, 2004
# At versions < 1 we expect the input mapping file to consist of three
# element tuples, comma seperated
#    remotehost remoterole localrole
# Note that the remotehost should be the a string which includes
# the distinguished name of the remote host, as serialised by the
# AttributeToken code.

from UserDict import UserDict
from AccessToken import AccessToken
from X500DN import X500DN

class AAmap:
    ''' This class handles the NDG role mapping for a web service. There
    are two main methods which are supported by two main internal dictionaries
    for efficiency:
                         For the <map> method we need to be able to return
    the local roles which are supported for the remotehost att certificate,
    ie, construct a dictionary keyed by remotehost, with the values being
    dictionaries which key the remoteroles onto local roles.
                         For the <getTrustedHosts> method we need to be
    a dictionary of what hosts are available for a given localrole
    '''
    
    def __init__(self,path2mapfile,path2ourDN):
        # we will need this for later
        self._inputpath=path2mapfile
        # get our own DN From a file, only needed once
        f=open(path2ourDN,'r')
        self.US=X500DN
        self.US.deserialise(f.readline())
        # now go get the map
        self._rolemap={}
        self._getmap={}
        self._read()

    def _read(self):
        ''' Open and read the mapping information from a file, by
        making two internal indices for efficiency: one dictionary
        keyed by remotehost, and one keyed by localrole'''
        f=open(self._inputpath,'r')
        lines=f.readlines()
        rh=X500DN()
        for line in lines:
            (remotehost,remoterole,localrole)=line.split(',')
            remotehostDN=rh.deserialise(remotehost)
            #first for the getTrustedHosts
            if localrole in self._getmap.keys():
                self._getmap[localrole].append(remotehost)
            else:
                self._getmap[localrole]=[remotehost]
            # and now to do the map
            if remotehost in self._rolemap.keys():
                self._rolemap[remotehost][remoterole:localrole]
            else:
                self._rolemap[remotehost]={remoterole:localrole}
        f.close()

    def restart(self):
        ''' Reread the information from the file '''
        self._getmap.clear()
        self._rolemap.clear()
        self._read()
    #
    # public methods
    #
    def map(self,remotecert):
        ''' Produces a local attribute cert from a remote certificate '''
        # convert remotecert XML version into python object
        Cert=AccessToken(dpat=remotecert)
        # construct a new token
        newToken=AccessToken(holder=Cert.holder,issuer=self.US)
        # only add stuff to it if their cert was valid and signed
        if Cert.checkSig() and Cert.checkValid():    
            remotehost=Cert.issuer.serialise()
            for item in remotecert.attributes:
                for key in self._rolemap[remotehost]:
                    newToken.add(self._rolemap[remotehost][remoterole])
        # now sign ours
        newToken.sign()
        # serialise back into XML and give it back
        return newToken.toxml()
        ### How do we mark it as a time-limited attribute certificate ??? ###
    
    def getTrustedHosts(self,role):
        #needs to be serialised into XML
        list=self._getmap[role]
        return list


if __name__=='__main__':

    print 'AAmap tests wont work yet ... need some input file '
    map=AAmap('mapfile','ourDN')

    

    
    

    

    

        
        
