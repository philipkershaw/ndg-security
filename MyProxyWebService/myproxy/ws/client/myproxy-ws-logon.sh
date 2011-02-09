#!/bin/bash
#
# Client script for web service interface to MyProxy logon based on openssl and
# curl
#
# @author P J Kershaw 25/05/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD - See top-level LICENCE file for licence details
#
# $Id$
cmdname=$(basename $0)
cmdline_opt=`getopt -o hU:l:So:c: --long help,uri:,username:,stdin_pass,out:ca-directory: -n "$cmdname" -- "$@"`

usage="Usage: $cmdname [-U MyProxy Web Service URI][-l username] ...\n
\n
   Options\n
       -h | --help\t\t\t\tDisplays usage\n
       -U | --uri\t\t<uri>\t\tMyProxy web service URI\n
       -l | --username\t<username>\tUsername for the delegated proxy (defaults to \$LOGNAME)\n
       -S | --stdin_pass\t\t\tpass password from stdin rather prompt from tty\n
       -o | --out\t\t<filepath>\tLocation of delegated proxy (default to stdout)\n
       -c | --ca-directory <directory path>\tDirectory containing the trusted\n
       \t\t\t\t\tCA (Certificate Authority) certificates.  These are used to\n
       \t\t\t\t\tverify the identity of the MyProxy Web Service.  Defaults to\n 
       \t\t\t\t\t${HOME}/.globus/certificates or\n
       \t\t\t\t\t/etc/grid-security/certificates if running as root.\n
"

if [ $? != 0 ] ; then
    echo -e $usage >&2 ;
    exit 1 ;
fi

eval set -- "$cmdline_opt"

while true ; do
    case "$1" in
        -h|--help) echo -e $usage ; exit 0 ;;
        -U|--uri) uri=$2 ; shift 2 ;;
        -l|--username) username=$2 ; shift 2 ;;
        -S|--stdin_pass) stdin_pass=True ; shift 1 ;;
        -o|--out) outfilepath=$2 ; shift 2 ;;
        --) shift ; break ;;
        *) echo "Error parsing command line" ; exit 1 ;;
    esac
done

if [ -z $uri ]; then
    echo -e Give the URI for the MyProxy web service logon request;
    echo -e $usage >&2 ;
    exit 1;
fi

# Default to LOGNAME if not set on command line
if [ -z $username ]; then
    username=${LOGNAME}
fi

# Read password
if [ $stdin_pass ]; then
    read password;
else
    stty -echo
    read -p "Enter MyProxy pass phrase: " password; echo
    stty echo
fi

# Set-up trust root
if [ ${X509_CERT_DIR} ]; then
    cadir=${X509_CERT_DIR}
elif [ "$username" = "root" ]; then
    cadir=/etc/grid-security/certificates
else
    cadir=${HOME}/.globus/certificates
fi

# Set output file path
if [ -z $outfilepath ]; then
    if [ ${X509_USER_PROXY} ]; then
        outfilepath=${X509_USER_PROXY}
    else
        # Default to stdout
        outfilepath=/dev/stdout
    fi
fi

# Make a temporary file location for the certificate request
certreqfilepath="/tmp/$UID-$RANDOM.csr"

# Generate key pair and request.  The key file is written to the 'key' var
key=$(openssl req -new -newkey rsa:2048 -nodes -keyout /dev/stdout -subj /CN=dummy -out $certreqfilepath 2> /dev/null)

# Post request to MyProxy web service passing username/password for HTTP Basic
# auth based authentication.  
# 
# Nb. Earlier versions of curl don't support --data-urlencode so use this 
# workaround instead...

# Alterations to change Base 64 encoding to URL safe Base 64
encoded_certreq=$(cat $certreqfilepath|sed s/+/%2B/g)

response=$(curl $uri --sslv3 -u $username:$password --data "certificate_request=$encoded_certreq" --capath $cadir -w " %{http_code}" -s -S)

responsemsg=$(echo "$response"|sed '$s/ *\([^ ]* *\)$//')
responsecode=$(echo $response|awk '{print $NF}')
if [ "$responsecode" != "200" ]; then
    echo "$responsemsg" >&2
    exit 1
fi

# Simple sanity check on response
if [[ $responsemsg != -----BEGIN\ CERTIFICATE-----* ]]; then
    echo "Expecting certificate in response; got:"
    echo "$responsemsg" >&2
    exit 1
fi

# Output certificate
echo "$responsemsg" > $outfilepath

# Add key 
echo "$key" >> $outfilepath
