'''
this script tests a list of urls for ssl expiry times
if they are self signed, it errors
if it's expired, it warns in red
if it's expiring in less than 20 days, it warns in yellow
if it is normal, not expired it prints results in grey
'''

import socket
import ssl
import datetime

# colors https://en.wikipedia.org/wiki/ANSI_escape_code
from colorama import init
init()

def ssl_expiry_datetime(hostname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    ctxt = ssl.create_default_context()
    conn = ctxt.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    
    # parse the string from the certificate into a Python datetime object
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)


def ssl_valid_time_remaining(hostname):
    expires = ssl_expiry_datetime(hostname)
    return expires - datetime.datetime.utcnow()

def ssl_expires_in(hostname, buffer_days=20):
    remaining = ssl_valid_time_remaining(hostname)

    # if the cert expires in less than two weeks, we should reissue it
    if remaining < datetime.timedelta(days=0):
        # cert has already expired - uhoh!
        return 1
    elif remaining < datetime.timedelta(days=buffer_days):
        # expires sooner than the buffer
        return 2
    else:
        # everything is fine
        return 3

# fixme: move list to json file
uris = {
'wellsfargo.com' : 443, 
'rubysash.com' : 443,
'github.com' : 443
#'qvsslrca2-ev-r.quovadisglobal.com' : 443,  # passes, but is revoked fixme
}


# check days remaining
passed = 1
for u in uris:

    # normalize colors to grey
    print('\033[93m', end='')

    try:
        ssl_valid_time_remaining(u)
    except:
        print('\033[31m'+"FAIL: "+'\033[31m',"?? days, 00:00:00.000000","\t",u)
        passed = 0
    else:
        if ssl_expires_in(u) == 1:
            print('\033[31m'+"EXP!: "+'\033[31m',ssl_valid_time_remaining(u),"\t",'\033[31m'+u)
        elif ssl_expires_in(u) == 2:
            print('\033[33m'+"PASS: "+'\033[33m',ssl_valid_time_remaining(u),"\t",'\033[33m'+u)
        else:
            print('\033[90m'+"PASS: "+'\033[90m',ssl_valid_time_remaining(u),"\t",'\033[90m'+u)

if passed == 1:
    print('\033[32m'+"ALL PASSED"+'\033[31m')
else:
    print('\033[31m'+"SOMETHING WRONG"+'\033[31m')

'''
Fix me:
is certificate revoked?
ex: https://revoked.grc.com

does domain name match?

is certificate expired?
ex: https://qvica1g3-e.quovadisglobal.com/

is it self signed?
ex: https://self-signed.badssl.com

is the RC4 cipher outdated?
ex: https://rc4.badssl.com/

is the DH key weak?
ex: https://dh480.badssl.com/

Does it pass vuln checks? (testssl.sh examples)
heartbleed, CCS, Ticketbleed, ROBOT, CRIME, Poodle, Logjam, Drown, Freak, Sweet32, Breach, Secure Fallback, Beast, etc?

Does it allow SSL v3?

What protocol does it use?  TLSv1.2?


'''