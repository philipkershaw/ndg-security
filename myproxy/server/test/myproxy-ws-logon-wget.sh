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
cmdline_opt=`getopt -o hU:l:So: --long help,uri:,username:,stdin_pass,out:: -n "$cmdname" -- "$@"`

usage="Usage: $cmdname [-U MyProxy Web Service URI][-l username] ...\n
\n
   Options\n
       -h | --help\t\t\t\tDisplays usage\n
       -U | --uri\t\t<uri>\t\tMyProxy web service URI\n
       -l | --username\t<username>\tUsername for the delegated proxy (defaults to \$LOGNAME)\n
       -S | --stdin_pass\t\t\tpass password from stdin rather prompt from tty\n
       -o | --out\t\t<filepath>\tLocation of delegated proxy (default to stdout)\n
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

# URL Encode certificate request - allow for '+' symbol in the base64 charset - 
# needs to be hex equivalent

# Post request to MyProxy web service passing username/password for HTTP Basic
# auth based authentication.  
encoded_certreq=$(cat $certreqfilepath|sed s/+/%2B/g)

response=$(wget --secure-protocol SSLv3 --ca-directory=$cadir \
--http-user=$username --http-password=$password \
--post-data "certificate_request=$encoded_certreq" \
-t 1 --auth-no-challenge $uri -O - 2>&1)

# Pull out the response code from the output
wget_statcode_line="HTTP request sent, awaiting response..."
responsecode=$(echo "$response"|grep "$wget_statcode_line"|awk '{print $6}')
if [ "$responsecode" != "200" ]; then
    echo "$responsemsg" >&2
    exit 1
fi

# Extract the certificate
cert=$(echo "$response" | openssl x509)
# Simple sanity check on extracted cert
if [[ $cert != -----BEGIN\ CERTIFICATE-----* ]]; then
    echo "Expecting certificate in response; got:"
    echo "$cert" >&2
    exit 1
fi

# Output certificate
echo "$cert" > $outfilepath

# Add key 
echo "$key" >> $outfilepath
