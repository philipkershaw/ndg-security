#Copyright (C) 2004 CCLRC & NERC
#    This software may be distributed under the terms of the 
#    Q Public License, version 1.0 or later
#
# Version 0.2 BNL November 30, 2004
# Format of AAmap file described on wiki.

from UserDict import UserDict
from AccessToken import AccessToken
from X500DN import X500DN
from SimpleSig import SimpleSig
from M2Crypto import X509

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
    
    def __init__(self,path2mapfile,ourpkeyfile,ourX509cert,therootcert):
        ''' Instantiate the AAmap instance, by loading all the necessary
        key files and instantiating the signature handler '''

        self._inputpath=path2mapfile
        
        # initialise the PKI stuff 
        
        self.handler=SimpleSig(ourpkeyfile,ourX509cert,therootcert)

        # now grab our distinguished name and load into self.us
        self.x509=X509.load_cert(ourX509cert)
        dn=self.x509.get_subject()
        self.us=X500DN(x509m2=dn)
        
        # now go get the map
        
        self._rolemap={}
        self._getmap={}
        self._read()
        
    def _read(self):
        ''' Open and read the mapping information from a file, by
        making two internal indices for efficiency: one dictionary
        keyed by remotehost, and one keyed by localrole'''

        def getText(nodelist):
            rc = ""
            for node in nodelist:
                if node.nodeType == node.TEXT_NODE:
                    rc = rc + node.data
            return rc

        # here we'll use minidom, so I learn about it, and because
        # it's lightweight

        from xml.dom import minidom
        doc=minidom.parse(self._inputpath)
        trusted=doc.getElementsByTagName("trusted")
        for host in trusted:
            remotehost=host.getAttribute("name")
            signatureFile=host.getElementsByTagName(
                "signatureFile")[0].firstChild.data
            roles=host.getElementsByTagName("role")
            for role in roles:
                remoterole,localrole=(role.getAttribute("remote"),
                              role.getAttribute("local"))
                print remotehost,remoterole,localrole
                #first for the getTrustedHosts
                if localrole in self._getmap.keys():
                    # only biff it in, if we haven't already added that host
                    if remotehost not in self._getmap[localrole]:
                        self._getmap[localrole].append(remotehost)
                else:
                    self._getmap[localrole]=[remotehost]
                # and now to do the map
                if remotehost in self._rolemap.keys():
                    self._rolemap[remotehost][remoterole]=localrole
                else:
                    self._rolemap[remotehost]={remoterole:localrole}
        doc.unlink()

    def restart(self):
        ''' Reread the configuration information from the files '''
        self._getmap.clear()
        self._rolemap.clear()
        self._read()
        self._loadcerts()
    #
    # public methods
    #
    def map(self,remotecert):
        ''' Produces a local attribute cert from a remote certificate '''
        # convert remotecert XML version into python object
        Cert=AccessToken(dpat=remotecert,handler=self.handler)
        # construct a new token
        newToken=AccessToken(holder=Cert.holder,issuer=self.us,
                             handler=self.handler)
        # only add stuff to it if their cert was valid and signed
        if Cert.checkSig() and Cert.checkValid():    
            remotehost=Cert.issuer.serialise()
            for item in remotecert.attributes:
                for key in self._rolemap[remotehost]:
                    newToken.add(self._rolemap[remotehost][remoterole])
        # now sign ours, noting that the signing method returns the
        # signed version as well as updating the document itself.
        return newToken.sign()
        
        ### How do we mark it as a time-limited attribute certificate ??? ###
    
    def getTrustedHosts(self,role):
        #needs to be serialised into XML, or does it ... done for you ...
        list=self._getmap[role]
        return list


if __name__=='__main__':

    print 'AAmap tests wont work yet ... need some input file '
    map=AAmap('map_config.xml','rsakey.pem','rsacert.pem','rootcert.pem')
    print map.getTrustedHosts('nerc')
    # can't test the att cert map until we understand the file handling.
    

    
    

    

    

        
        
