"""SQLObject Object Relational Mapper database interface for NDG Security
CredentialRepository

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/10/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'

# SQLObject Database interface
from sqlobject import *

# For parsing of properties files

# For parsing of properties file
try: # python 2.5
    from xml.etree import cElementTree as ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree as ElementTree

from CredWallet import CredRepos as CredReposBase
from CredWallet import CredReposError


#_____________________________________________________________________________
class CredRepos(CredReposBase):
    """Interface to Credential Repository Database
    
    Nb. inherits from CredWallet.CredRepos to ensure correct interface
    to the wallet"""

    # valid configuration property keywords
    __validKeys = ['dbURI']
    
    
    #_________________________________________________________________________    
    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Initialise Credentials Repository Database object.

        If the connection string or properties file is set a connection
        will be made

        dbURI:              <db type>://<username>:<passwd>@<hostname>/dbname
        propFilePath: file path to properties file

        Nb. propFilePath setting overrides input dbURI
        """
            
        self.__con = None
        self.__prop = {}
        
        if propFilePath is not None:
            
            # Read database URI set in file
            self.readProperties(propFilePath, dbPPhrase=dbPPhrase)
            
        elif prop != {}:
            
            # Database URI may have been set as an input keyword argument
            self.setProperties(dbPPhrase=dbPPhrase, **prop)


    #_________________________________________________________________________    
    def __setConnection(self,
                        dbType=None,
                        dbUserName=None,
                        dbPPhrase=None,
                        dbHostname=None,
                        dbName=None,
                        dbURI=None,
                        chkConnection=True):
        """Establish a database connection from a database URI

        pass a URI OR the parameters to construct the URI
            
        dbURI: "<db type>://<username>:<passwd>:<hostname>/dbname"

        or

        dbURI: "<db type>://<username>:%PPHRASE%:<hostname>/dbname"
        + passPhrase

        - %PPHRASE% is substituted with the input passPhrase keyword
        
        or
        
        dbType:         database type e.g. 'mysql'
        dbUserName:     username
        dbPPhrase:      pass-phrase
        dbHostname:     name of host where database resides
        dbName:         name of the database


        chkConnection:  check that the URI is able to connect to the 
        """

        try:
            if dbURI:
                # Check for pass-phrase variable set in URI '%PPHRASE%'
                dbURIspl = dbURI.split('%')
                if len(dbURIspl) == 3:
                    
                    if dbPPhrase is None:
                        raise CredReposError, "No database pass-phrase set"
                    
                    dbURI = dbURIspl[0] + dbPPhrase + dbURIspl[2]
                
            else:
                # Construct URI from individual inputs
                dbURI = dbType + '://' + dbUserName + ':' + dbPPhrase + \
                        ':' + dbHostname + '/' + dbName
        except Exception, e:
            # Checking form missing keywords
            raise CredReposError, "Error creating database URI: %s" % e

        try:
            self.__con = connectionForURI(dbURI)
        except Exception, e:
            raise CredReposError, "Error creating database connection: %s" % e

        if chkConnection:
            try:
                self.__con.makeConnection()
                
            except Exception, e:
                raise CredReposError, \
                        "Error connecting to Credential Repository: %s" % e

            
        # Copy the connection object into the table classes
        CredRepos.UserID._connection = self.__con
        CredRepos.UserCredential._connection = self.__con
          

    #_________________________________________________________________________    
    def setProperties(self, dbPPhrase=None, **prop):
        """Update existing properties from an input dictionary
        Check input keys are valid names"""
        
        for key in prop.keys():
            if key not in self.__validKeys:
                raise CredReposError, "Property name \"%s\" is invalid" % key
                
        self.__prop.update(prop)


        # Update connection setting
        if 'dbURI' in prop:
            self.__setConnection(dbURI=prop['dbURI'], dbPPhrase=dbPPhrase)


    #_________________________________________________________________________    
    def readProperties(self,
                       propFilePath=None,
                       propElem=None,
                       dbPPhrase=None):
        """Read the configuration properties for the CredentialRepository

        propFilePath|propElem

        propFilePath: set to read from the specified file
        propElem:     set to read beginning from a cElementTree node"""

        if propFilePath is not None:

            try:
                tree = ElementTree.parse(propFilePath)
                propElem = tree.getroot()
                
            except IOError, e:
                raise CredReposError, \
                                "Error parsing properties file \"%s\": %s" % \
                                (e.filename, e.strerror)

            except Exception, e:
                raise CredReposError, \
                                "Error parsing properties file \"%s\": %s" % \
                                (propFilePath, str(e))

        if propElem is None:
            raise CredReposError, \
    "Error parsing properties file \"%s\": root element is not defined" % \
                                propFilePath


        # Read properties into a dictionary
        prop = {}
        for elem in propElem:
                    
            # Check for environment variables in file paths
            tagCaps = elem.tag.upper()
            if 'FILE' in tagCaps or 'PATH' in tagCaps or 'DIR' in tagCaps:
                elem.text = os.path.expandvars(elem.text)

            prop[elem.tag] = elem.text
            
        self.setProperties(dbPPhrase=dbPPhrase, **prop)

            
    #_________________________________________________________________________    
    def addUser(self, userName, dn):
        """A new user to Credentials Repository"""
        try:
            self.UserID(userName=userName, dn=dn)

        except Exception, e:
            raise CredReposError, "Error adding new user '%s': %s" % \
                                                                (userName, e)


    #_________________________________________________________________________    
    def auditCredentials(self, dn=None, **attCertValidKeys):
        """Check the attribute certificates held in the repository and delete
        any that have expired

        dn:                Only audit for the given user distinguished Name.
                           if not set, all records are audited
        attCertValidKeys:  keywords which set how to check the Attribute
                           Certificate e.g. check validity time, XML
                           signature, version etc.  Default is check
                           validity time only"""

        if attCertValidKeys == {}:
            # Default to check only the validity time
            attCertValidKeys = {    'chkTime':          True,
                                    'chkVersion':       False,
                                    'chkProvenance':    False,
                                    'chkSig':           False }
            
        try:
            if dn:
                # Only audit for the given user distinguished Name
                credList = self.UserCredential.selectBy(dn=dn)
            else:
                # Audit all credentials
                credList = self.UserCredential.select()
            
        except Exception, e:
            raise CredReposError,"Selecting credentials from repository: " + \
                                 str(e)

        # Iterate through list of credentials deleting records where the
        # certificate is invalid
        try:
            for cred in credList:
                attCert = AttCertParse(cred.attCert)
                
                if not attCert.isValid(**attCertValidKeys):
                    self.UserCredential.delete(cred.id)
                    
        except Exception, e:
            try:
                raise CredReposError, "Deleting credentials for '%s': %s" % \
                                                       (cred.dn, e)
            except:
                raise CredReposError, "Deleting credentials: %s" % e


    #_________________________________________________________________________    
    def getCredentials(self, dn):
        """Get the list of credentials for a given user's DN"""

        try:
            return self.UserCredential.selectBy(dn=dn)
            
        except Exception, e:
            raise CredReposError, "Selecting credentials for %s: %s" % (dn, e)


    #_________________________________________________________________________    
    def addCredentials(self, dn, attCertList):
        """Add new attribute certificates for a user.  The user must have
        been previously registered in the repository

        dn:             users Distinguished name
        attCertList:   list of attribute certificates"""
        
        try:
            userCred = self.UserID.selectBy(dn=dn)
            
            if userCred.count() == 0:
                # Add a new user record HERE instead of at user registration
                # time.  This decouples CredentialRepository from MyProxy and
                # user registration process. Previously, a user not recognised
                # exception would have been raised here.  'userName' field
                # of UserID table is now perhaps superfluous.
                #
                # P J Kershaw 26/04/06 
                self.addUser(X500DN(dn)['CN'], dn)

        except Exception, e:
            raise CredReposError, "Checking for user \"%s\": %s" % (dn, e)

        
        # Carry out check? - filter out certs in db where a new cert
        # supercedes it - i.e. expires later and has the same roles
        # assigned - May be too complicated to implement
        #uniqAttCertList = [attCert for attCert in attCertList \
        #    if min([attCert == cred.attCert for cred in userCred])]
        
                
        # Update database with new entries
        try:
            for attCert in attCertList:
                self.UserCredential(dn=dn, attCert=str(attCert))

        except Exception, e:
            raise CredReposError, "Adding new user credentials for " + \
                                  "user %s: %s" % (dn, str(e))


    #_________________________________________________________________________    
    def _initTables(self, prompt=True):
        """Use with EXTREME caution - this method will initialise the database
        tables removing any previous records entered"""
 
        if prompt:
            resp = raw_input(\
        "Are you sure you want to initialise the database tables? (yes/no) ")
    
            if resp.upper() != "YES":
                print "Tables unchanged"
                return
        
        self.UserID.createTable()
        self.UserCredential.createTable()
        print "Tables created"

            
    #_________________________________________________________________________
    # Database tables defined using SQLObject derived classes
    # Nb. These are class variables of the CredRepos class
    class UserID(SQLObject):
        """SQLObject derived class to define Credentials Repository db table
        to store user information"""

        # to be assigned to connectionForURI(<db URI>)
        _connection = None

        # Force table name
        _table = "UserID"

        userName = StringCol(dbName='userName', length=30)
        dn = StringCol(dbName='dn', length=128)


    class UserCredential(SQLObject):
        """SQLObject derived class to define Credentials Repository db table
        to store user credentials information"""

        # to be assigned to connectionForURI(<db URI>)
        _connection = None

        # Force table name
        _table = "UserCredential"

        
        # User name field binds with UserCredential table
        dn = StringCol(dbName='dn', length=128)

        # Store complete attribute certificate text
        attCert = StringCol(dbName='attCert')
