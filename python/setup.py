#!/usr/bin/env python

"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project

P J Kershaw 24/04/06

Copyright (C) 2006 CCLRC & NERC

This software may be distributed under the terms of the Q Public License,
version 1.0 or later.
"""
from distutils.core import setup
import os

setupKeys = \
{
    'name':           'NDG-Security',
    'version':        '0.68',
    'description':    'NERC DataGrid Security Utilities',
    'author':         'P J Kershaw',
    'author_email':   'P.J.Kershaw@rl.ac.uk',
    'url':            'http://proj.badc.rl.ac.uk/ndg',
    'packages':       ['NDG'],
}
setup(**setupKeys)