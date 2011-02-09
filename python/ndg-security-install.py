#!/usr/bin/env python
"""Install NDG Server package with M2Crypto build settings and to include
Twisted 

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/03/07"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__revision__ = '$Id$'


import os, sys
import shutil # For creating config dir
import urllib
import optparse
from ConfigParser import SafeConfigParser
from subprocess import call
from setuptools.command.easy_install import main

import logging
log = logging.getLogger(__name__)
      
class SecurityInstallError(Exception):
    """Errors related to security installation"""
    
class SecurityInstall(object):
    '''Wrapper class for NDG security installation
    
    A wrapper is required over and above easy_install as additional setup
    steps are required to enable for example custom build settings for 
    M2Crypto
    
    @cvar dependencyLink: default location for dependencies
    @type dependencyLink: string
    
    @cvar defaultTwistedURI: default location for Twisted download
    @type param: string 
    
    @cvar configDir: default location for configuration directory "conf"
    @type configDir: string'''
    
    dependencyLink = "http://ndg.nerc.ac.uk/dist/"  
    defaultTwistedURI = \
'http://tmrc.mit.edu/mirror/twisted/Twisted/2.2/TwistedSumo-2006-02-12.tar.bz2'
    configDir = os.path.join("/etc", "ndg", "security", "conf")
    
    def __call__(self):
        self.main()
        
    def main(self):
        '''Parse command line args and execute the installation'''
        
        parser = optparse.OptionParser()
        
        parser.add_option("-a",
                          "--install-all",
                          dest="installAll",
                          action="store_true",
                          default=False,
                          help="Install client AND server packages.")
        
        parser.add_option("-c",
                          "--install-client",
                          dest="installClient",
                          action="store_true",
                          default=False,
                          help="Install client package only.")
        
        parser.add_option("-s",
                          "--install-server",
                          dest="installServer",
                          action="store_true",
                          default=False,
                          help="Install server package only.")
        
        parser.add_option("-u",
                          "--install-unittests",
                          dest="installUnitTests",
                          action="store_true",
                          default=False,
                          help="Install unit test package only.")
        
        parser.add_option("-o",
                          "--openssl-path",
                          dest="opensslPath",
                          default='/usr/local/ssl',
                          help="Path to openssl for M2Crypto to link with")
        
        parser.add_option("-n",
                          "--no-twisted",
                          dest="noTwisted",
                          action="store_true",
                          default=False,
                          help=\
"""Skip Twisted install.  This option applies to the \"all\" and \"server\"
package options only.  Twisted is not needed for the client.""")
        
        parser.add_option("-t",
                          "--twisted-uri",
                          dest="twistedURI",
                          default=self.__class__.defaultTwistedURI,
                          help=\
"""Provide an alternative location for Twisted download.  A .tar.bz type file
is expected.  The default is \"%s\"""" % self.__class__.defaultTwistedURI)
        
        parser.add_option("-f",
                          "--find-links",
                          dest="dependencyLinks",
                          default=self.__class__.dependencyLink,
                          help=\
                      'Set URLs to locate packages.  The default is "%s"' % \
                      self.__class__.dependencyLink)
        
        parser.add_option("-U",
                          "--upgrade",
                          dest="upgrade",
                          action="store_true",
                          default=False,
                          help=\
          'force upgrade (search PyPI/dependency links for latest version)')
    
        configOpts = ("-C", "--config-dir")
        parser.add_option(dest="configDir",
                          default=self.__class__.configDir,
                          help=\
"""Specify a location for configuration files (server package only).  The
default is \"%s\"""" % self.__class__.configDir,
                          *configOpts)
    
        self.opt, args = parser.parse_args()
    
        # Sanity check
        nInstallArgs = sum((self.opt.installClient, 
                            self.opt.installServer,
                            self.opt.installUnitTests, 
                            self.opt.installAll))
        if not nInstallArgs:
            parser.error("At least one install option must be set")
            
        elif nInstallArgs > 1:
            parser.error("Only one install option may be set")
 
        # Set M2Crypto build settings in a distutils config file
        self.initM2CryptoDependencies()  
    
        # Installation based on flags set
        if self.opt.upgrade:
            args = ['-U']
        else:
            args = []
      
        # Add links for dependencies  
        args += ['-f', self.opt.dependencyLinks]

        if self.opt.installClient:
            log.info("Installing ndg-security-client ...")
            args += ["ndg_security_client"]
            main(args)
            
        elif self.opt.installServer:
            log.info("Installing ndg-security-server ...")
            args += ["ndg_security_server"]
            main(args)
            self.installTwisted()
            
            # Config dir is part of server package only
            self.createConfigDir()
            
        elif self.opt.installUnitTests:
            log.info("Installing ndg-security-test ...")
            args += ["ndg_security_test"]
            main(args)
            self.installTwisted()
           
        elif self.opt.installAll:
            log.info("Installing all ...")
            args += ["ndg_security", "ndg_security_test"]
            if self.opt.upgrade:
                # If upgrade is set dependencies for ndg_security aren't
                # updated - they need to be added explicitly
                args += ["ndg_security_common", 
                         "ndg_security_server",
                         "ndg_security_client"] 
            main(args)
            self.installTwisted()
            
            # Config dir is part of server package
            self.createConfigDir()
            
            
    def initM2CryptoDependencies(self):       
        '''Set-up link path for openssl for M2Crypto build by creating a 
        distutils config file containing the include file and library file 
        paths'''
        log.info("Initialising M2Crypto set-up ...")
        
        opensslInclPath = os.path.join(self.opt.opensslPath, 'include')
        opensslLibPath = os.path.join(self.opt.opensslPath, 'lib')
        
        distutilsCfgFilePath = os.path.join(sys.prefix,
                                            'lib',
                                            'python%s' % sys.version[:3],
                                            'distutils',
                                            'distutils.cfg')
        configParser = SafeConfigParser()
        
        if configParser.read(distutilsCfgFilePath):
            # File already exists
            if not configParser.has_section('build_ext'):
                configParser.add_section('build_ext')
            
            if configParser.has_option('build_ext', 'include_dirs'):
                existingInclDirs=configParser.get('build_ext', 'include_dirs')
                
                if opensslInclPath not in existingInclDirs.split():
                    includeDirs = "%s %s" % (opensslInclPath,existingInclDirs)
                    configParser.set('build_ext', 'include_dirs', includeDirs)
            else:
                configParser.set('build_ext', 'include_dirs', opensslInclPath)
            
            if configParser.has_option('build_ext', 'library_dirs'):
                existingLibDirs = configParser.get('build_ext','library_dirs')
                
                if opensslLibPath not in existingLibDirs.split():
                    libraryDirs = "%s %s" % (opensslLibPath, existingLibDirs)
                    configParser.set('build_ext', 'library_dirs', libraryDirs)
            else:
                configParser.set('build_ext', 'library_dirs', opensslLibPath)
                                 
        else:
            # No config file present - make one
            configParser.add_section('build_ext')
            configParser.set('build_ext', 'include_dirs', opensslInclPath)
            configParser.set('build_ext', 'library_dirs', opensslLibPath)
            
        try:
            configParser.write(open(distutilsCfgFilePath, 'w'))
        except IOError:
            # distutils dir may not be installed - try local dir as back-up
            # option
            distutilsCfgFilePath = os.path.join(os.environ['HOME'],
                                                '.pydistutils.cfg')
            configParser.write(open(distutilsCfgFilePath, 'w'))
    
    
    def installTwisted(self):
        '''Download and install twisted manually as it is not egg compatible
        '''
        
        if self.opt.noTwisted:
            return
        
        log.info("Installing Twisted: %s ..." % self.opt.twistedURI)
        
        # Install Twisted sumo
        try:
            twistedTarBz = os.path.basename(self.opt.twistedURI)    
            urllib.urlretrieve(self.opt.twistedURI, twistedTarBz)
            
        except IOError, (errMsg, e):
            raise SecurityInstallError, \
                'Error retrieving Twisted from "%s": %s' % \
                                                (self.opt.twistedTarURI, e[1])
        except Exception, e:
            raise SecurityInstallError, \
                'Error retrieving Twisted from "%s": %s' % \
                                                (self.opt.twistedTarURI, e)

        import tarfile
       
        twistedTar = tarfile.open(twistedTarBz, 'r:bz2')
        for tarInfo in twistedTar:
            twistedTar.extract(tarInfo)
       
        try:
            twistedDir=os.path.splitext(os.path.splitext(twistedTarBz)[0])[0]
        except Exception:
            raise SecurityInstallError, \
            'Error getting Twisted dir path from tar.bz file name: "%s"' % \
                twistedTarBz
        
        os.chdir(twistedDir)
        try: 
            retCode = call([os.path.join(sys.prefix, 'bin', 'python'), 
                            'setup.py', 
                            'install'])
        except OSError, e:
            raise SecurityInstallError, \
                        "Error calling setup install for Twisted: " + str(e)
        
        if retCode != 0:
            raise SecurityInstallError, "Twisted setup install returned %d" %\
                                        retCode
        
        os.chdir('..')


    def createConfigDir(self):
        """Copy configuration files for services from the server egg into
        a config area.  The default is /etc/ndg/security/conf"""
        
        # Skip if not set
        if not self.opt.configDir: 
            return
        
        log.info('Copying configuration directory to "%s"'%self.opt.configDir)
        
        # Otherwise create - fix to rwx for owner and group only
        confDirPath = os.path.dirname(self.opt.configDir)
        try:
            os.makedirs(confDirPath, mode=0770)
        except OSError, e:
            if e.errno != 17:
                # errno=17 -> file already exists - it's OK if directory is 
                # already present
                raise SecurityInstallError, \
                   "Creating configuration directory: %s" % e
        
        # Locate conf directory in active egg
        #
        # pkg_resources import MUST be go here otherwise in an update to 
        # existing eggs, the latest version will be reported as the one
        # you're replacing instead of the new one
        import pkg_resources

        # Get distribution version info
        serverDistro = pkg_resources.get_distribution('ndg-security-server')
        eggConfigDir = os.path.join(serverDistro.location, 'ndg', 'security',
                                    'server', 'conf')

        configDirVers = "%s.%s" % (self.opt.configDir, serverDistro.version)
        # Copy over conf directory from egg
        try:
            shutil.copytree(eggConfigDir, configDirVers)
        except OSError, e:
            if e.errno != 17:
                raise SecurityInstallError, \
                    "Copying configuration directory: %s" % e

        # Create a symbolic link to the conf.<version> dir - first check the
        # link doesn't already exist
        if os.path.islink(self.opt.configDir):
            os.unlink(self.opt.configDir)
            
        try:
            os.symlink(configDirVers, self.opt.configDir)
        except OSError, e:
            raise SecurityInstallError, \
                "Making a symbolic link %s -> %s: %s" % (self.opt.configDir, 
                                                         configDirVers, 
                                                         e)
if __name__ == "__main__":
    SecurityInstall()()
      