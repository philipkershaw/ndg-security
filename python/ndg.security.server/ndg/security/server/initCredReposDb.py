#!/usr/bin/env python
"""NDG Security - initialisation script for MySQL Credential Repository
database

Use with care!  It initialise all the tables in the database.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "25/04/06"
__copyright__ = "(C) 2007 STFC & NERC"
__license__ = \
"""This software may be distributed under the terms of the Q Public 
License, version 1.0 or later."""
__contact__ = "P.J.Kershaw@rl.ac.uk"
__author__ = "P J Kershaw"
__revision__ = "$Id$"

# Command line processing
import sys
import os
import optparse
import getpass

from ndg.security.server.Session import *


def main():
    parser = optparse.OptionParser()
    parser.add_option("-u",
                      "--username",
                      dest="username",
                      help="Database username")

    parser.add_option("-n",
                      "--hostname",
                      dest="hostname",
                      help="database hostname - default is \"localhost\"")

    parser.add_option("-D",
                      "--database-name",
                      dest="dbName",
                      help="database name - default is \"ndgCredRepos\"")

    (opt, args) = parser.parse_args()

    if not opt.username:
        sys.stderr.write("Error, No username set.\n\n")
        parser.print_help()
        sys.exit(1)

    if not opt.hostname:
        opt.hostname = "localhost"

    if not opt.dbName:
        opt.dbName = "ndgCredRepos"


    # Obtain from prompt
    try:
        password = getpass.getpass(prompt="Database password: ")
    except KeyboardInterrupt:
        sys.exit(1)


    try:
        dbURI = "mysql://%s:%s@%s/%s" % \
                            (opt.username, password, opt.hostname, opt.dbName)
        credRepos = SessionMgrCredRepos(dbURI=dbURI)
    except Exception, e:
        sys.stderr.write("%s\n" % str(e))
        sys.exit(1)

    # This method prompts the user for confirmation of table initialisation
    try:
        credRepos._initTables()
    except Exception, e:
        sys.stderr.write("Error creating tables: %s\n" % str(e))

if __name__ == "__main__":
    main()
