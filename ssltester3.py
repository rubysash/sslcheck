'''
SSL Tester

Test SSL Expiry and a few other things about list of URLs
Needs an xlsx with a list of URLs in it.
Assumes all are https: and port is 443
Author: james@rubysash.com / bfraze@dtcc.com
Date: 08/10/2020



todo:
    - add email notification warning if too close to expire
    - look at poodle or other known vulns
    - add in tcp handshake time
    - add in dns time to monitor dns requests
    - add in total page load time
    - check page text for known and/or fingerprint
    - warn on status code alerts like 500 or !200
    - pull and id server version?
    - fix up the ctrl c thing.   It works but not like I intended
    - put entire thing in tkinter so others can more easily use it
    - store into over time graph on a sql type database


topics learned/refreshed:
    modules
    ctrl+c without error
    threading
    benchmarking
    dictionary of list data structure
    loops
    definitions
    time formatting
    time deltas
    ssl and https basic checks
    json read/write


# write it out to json so I can just run it from a json load later
print("Writing 'sites.json' file...")
with open ('sites.json', 'w') as outfile:
    json.dump(sites, outfile, indent=2)

# todo: create function to add sites to data easily

VERSION HISTORY
1.0 - Release, colorized, multithreaded, reads from xlsx
1.1 - Correct header errors, padded URL and Cipher type
1.2 - Verify if xlsx type data or not
1.3 - Verify if file even exists o rcan be opened
1.4 - Added fail checks for 403,404, etc
1.5 - added errors for many wrong cert problems
1.6 - file magic doesn't work on windows, added logic for that


---------------
User config:
---------------
'''

# how many threads do you want to spawn?
thread_max = 200

# for my ego
version = '1.6'

# do you want the xtra info?
verbosity = 0

# using test data or using the inputs?
testdata = 1

"""
------------
Sample Output (testsdata)
------------
C:\git\sslcheck>python ssltester3.py sites.xlsx Sheet1 2
  using test data!!!  xlsx and choices are ignored
  SSL Test, V1.6 is Running (200 threads) Press CTRL+C to exit.
ID      TLS     SSL     DAYS    EXPIRE DATE                     LENGTH  CIPHER TTYPE                    URL:PORT                                STATUS
 1000   --      --      --      --                              --      --                              dsdtestprovider.badssl.com:443          CERTIFICATE_VERIFY_FAILED
 1001   TLSv1.2 3       -549    Feb 10 12:00:00 2022 GMT        1024    ECDHE-ECDSA-AES128-GCM-SHA256   ecc256.badssl.com:443                   200
 1002   TLSv1.2 3       -257    Apr 24 20:08:56 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     vimeo.com:443                           200
 1003   TLSv1.2 3       -95     Nov 13 12:00:00 2020 GMT        2048    ECDHE-RSA-AES256-GCM-SHA384     mozilla.org:443                         200
 1004   TLSv1.2 3       -679    Jun 20 10:15:02 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     europa.eu:443                           200
 1005   --      --      --      --                              --      --                              medium.com:443                          403
 1006   TLSv1.2 3       -45     Sep 25 03:21:36 2020 GMT        2048    ECDHE-ECDSA-CHACHA20-POLY1305   howsmyssl.com:443                       200
 1007   TLSv1.2 3       -429    Oct 13 12:00:00 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     1000-sans.badssl.com:443                200
 1008   --      --      --      --                              --      --                              10000-sans.badssl.com:443               EXCESSIVE_MESSAGE_SIZE
 1009   --      --      --      --                              --      --                              3des.badssl.com:443                     SSLV3_ALERT_HANDSHAKE_FAILURE
 1010   --      --      --      --                              --      --                              captive-portal.badssl.com:443           CERTIFICATE_VERIFY_FAILED
 1011   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    ECDHE-RSA-AES256-SHA384         cbc.badssl.com:443                      200
 1012   --      --      --      --                              --      --                              client-cert-missing.badssl.com:443      400
 1013   --      --      --      --                              --      --                              client.badssl.com:443                   400
 1014   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh-composite.badssl.com:443             200
 1015   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh-small-subgroup.badssl.com:443        200
 1016   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh1024.badssl.com:443                   200
 1017   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh2048.badssl.com:443                   200
 1018   --      --      --      --                              --      --                              dh480.badssl.com:443                    DH_KEY_TOO_SMALL
 1019   --      --      --      --                              --      --                              dh512.badssl.com:443                    DH_KEY_TOO_SMALL
 1020   --      --      --      --                              --      --                              dsdtestprovider.badssl.com:443          CERTIFICATE_VERIFY_FAILED
 1021   TLSv1.2 3       -549    Feb 10 12:00:00 2022 GMT        1024    ECDHE-ECDSA-AES128-GCM-SHA256   ecc256.badssl.com:443                   200
 1022   TLSv1.2 3       -549    Feb 10 12:00:00 2022 GMT        1024    ECDHE-ECDSA-AES128-GCM-SHA256   ecc384.badssl.com:443                   200
 1023   --      --      --      --                              --      --                              edellroot.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1024   --      --      --      --                              --      --                              expired.badssl.com:443                  CERTIFICATE_VERIFY_FAILED
 1025   TLSv1.2 3       -730    Aug 10 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     extended-validation.badssl.com:443      200
 1026   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     hsts.badssl.com:443                     200
 1027   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     https-everywhere.badssl.com:443         200
 1028   --      --      --      --                              --      --                              incomplete-chain.badssl.com:443         CERTIFICATE_VERIFY_FAILED
 1029   --      --      --      --                              --      --                              invalid-expected-sct.badssl.com:443     CERTIFICATE_VERIFY_FAILED
 1030   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     lock-title.badssl.com:443               200
 1031   TLSv1.2 3       -69     Oct 18 09:02:07 2020 GMT        2048    ECDHE-ECDSA-AES256-GCM-SHA384   en.wikipedia.org:443                    200
 1032   TLSv1.2 3       -127    Dec 15 20:11:21 2020 GMT        2048    ECDHE-RSA-CHACHA20-POLY1305     wordpress.org:443                       200
 1033   --      --      --      --                              --      --                              mitm-software.badssl.com:443            CERTIFICATE_VERIFY_FAILED
 1034   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed-favicon.badssl.com:443            200
 1035   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed-form.badssl.com:443               200
 1036   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed-script.badssl.com:443             200
 1037   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed.badssl.com:443                    200
 1038   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mozilla-intermediate.badssl.com:443     200
 1039   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    ECDHE-RSA-AES256-GCM-SHA384     mozilla-modern.badssl.com:443           200
 1040   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mozilla-old.badssl.com:443              200
 1041   --      --      --      --                              --      --                              no-common-name.badssl.com:443           CERTIFICATE_VERIFY_FAILED
 1042   TLSv1.2 3       -429    Oct 13 12:00:00 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     no-sct.badssl.com:443                   200
 1043   --      --      --      --                              --      --                              no-subject.badssl.com:443               CERTIFICATE_VERIFY_FAILED
 1044   --      --      --      --                              --      --                              null.badssl.com:443                     SSLV3_ALERT_HANDSHAKE_FAILURE
 1045   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     pinning-test.badssl.com:443             200
 1046   --      --      --      --                              --      --                              preact-cli.badssl.com:443               CERTIFICATE_VERIFY_FAILED
 1047   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     preloaded-hsts.badssl.com:443           200
 1048   --      --      --      --                              --      --                              rc4-md5.badssl.com:443                  SSLV3_ALERT_HANDSHAKE_FAILURE
 1049   --      --      --      --                              --      --                              rc4.badssl.com:443                      SSLV3_ALERT_HANDSHAKE_FAILURE
 1050   TLSv1.2 3       -424    Oct  8 12:00:00 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     revoked.badssl.com:443                  200
 1051   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     rsa2048.badssl.com:443                  200
 1052   TLSv1.2 3       -630    May  2 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     rsa4096.badssl.com:443                  200
 1053   TLSv1.2 3       -595    Mar 28 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     rsa8192.badssl.com:443                  200
 1054   --      --      --      --                              --      --                              self-signed.badssl.com:443              CERTIFICATE_VERIFY_FAILED
 1055   --      --      --      --                              --      --                              sha1-2016.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1056   --      --      --      --                              --      --                              sha1-2017.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1057   --      --      --      --                              --      --                              sha1-intermediate.badssl.com:443        CERTIFICATE_VERIFY_FAILED
 1058   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     sha256.badssl.com:443                   200
 1059   TLSv1.2 3       -599    Apr  1 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     sha384.badssl.com:443                   200
 1060   TLSv1.2 3       -599    Apr  1 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     sha512.badssl.com:443                   200
 1061   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     spoofed-favicon.badssl.com:443          200
 1062   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    AES256-GCM-SHA384               static-rsa.badssl.com:443               200
 1063   --      --      --      --                              --      --                              subdomain.preloaded-hsts.badssl.com:443 CERTIFICATE_VERIFY_FAILED
 1064   --      --      --      --                              --      --                              superfish.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1065   --      --      --      --                              --      --                              untrusted-root.badssl.com:443           CERTIFICATE_VERIFY_FAILED
 1066   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     upgrade.badssl.com:443                  200
 1067   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    ECDHE-RSA-AES256-SHA384         very.badssl.com:443                     200
 1068   --      --      --      --                              --      --                              webpack-dev-server.badssl.com:443       CERTIFICATE_VERIFY_FAILED
 1069   --      --      --      --                              --      --                              wrong.host.badssl.com:443               CERTIFICATE_VERIFY_FAILED
 1070   --      --      --      --                              --      --                              self-signed.badssl.com:443              CERTIFICATE_VERIFY_FAILED
 1071   TLSv1.2 3       -45     Sep 25 03:21:36 2020 GMT        2048    ECDHE-ECDSA-CHACHA20-POLY1305   howsmyssl.com:443                       200
 1072   TLSv1.2 3       -429    Oct 13 12:00:00 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     1000-sans.badssl.com:443                200
 1073   --      --      --      --                              --      --                              10000-sans.badssl.com:443               EXCESSIVE_MESSAGE_SIZE
 1074   --      --      --      --                              --      --                              3des.badssl.com:443                     SSLV3_ALERT_HANDSHAKE_FAILURE
 1075   --      --      --      --                              --      --                              captive-portal.badssl.com:443           CERTIFICATE_VERIFY_FAILED
 1076   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    ECDHE-RSA-AES256-SHA384         cbc.badssl.com:443                      200
 1077   --      --      --      --                              --      --                              client-cert-missing.badssl.com:443      400
 1078   --      --      --      --                              --      --                              client.badssl.com:443                   400
 1079   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh-composite.badssl.com:443             200
 1080   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh-small-subgroup.badssl.com:443        200
 1081   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    DHE-RSA-AES128-GCM-SHA256       dh1024.badssl.com:443                   200
 1082   TLSv1.2 3       -549    Feb 10 12:00:00 2022 GMT        1024    ECDHE-ECDSA-AES128-GCM-SHA256   ecc384.badssl.com:443                   200
 1083   --      --      --      --                              --      --                              edellroot.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1084   --      --      --      --                              --      --                              expired.badssl.com:443                  CERTIFICATE_VERIFY_FAILED
 1085   TLSv1.2 3       -730    Aug 10 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     extended-validation.badssl.com:443      200
 1086   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     hsts.badssl.com:443                     200
 1087   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     https-everywhere.badssl.com:443         200
 1088   --      --      --      --                              --      --                              incomplete-chain.badssl.com:443         CERTIFICATE_VERIFY_FAILED
 1089   --      --      --      --                              --      --                              invalid-expected-sct.badssl.com:443     CERTIFICATE_VERIFY_FAILED
 1090   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     lock-title.badssl.com:443               200
 1091   --      --      --      --                              --      --                              webpack-dev-server.badssl.com:443       CERTIFICATE_VERIFY_FAILED
 1092   --      --      --      --                              --      --                              wrong.host.badssl.com:443               CERTIFICATE_VERIFY_FAILED
 1093   --      --      --      --                              --      --                              mitm-software.badssl.com:443            CERTIFICATE_VERIFY_FAILED
 1094   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed-favicon.badssl.com:443            200
 1095   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed-form.badssl.com:443               200
 1096   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed-script.badssl.com:443             200
 1097   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mixed.badssl.com:443                    200
 1098   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mozilla-intermediate.badssl.com:443     200
 1099   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    ECDHE-RSA-AES256-GCM-SHA384     mozilla-modern.badssl.com:443           200
 1100   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     mozilla-old.badssl.com:443              200
 1101   --      --      --      --                              --      --                              no-common-name.badssl.com:443           CERTIFICATE_VERIFY_FAILED
 1102   TLSv1.2 3       -429    Oct 13 12:00:00 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     no-sct.badssl.com:443                   200
 1103   --      --      --      --                              --      --                              no-subject.badssl.com:443               CERTIFICATE_VERIFY_FAILED
 1104   --      --      --      --                              --      --                              null.badssl.com:443                     SSLV3_ALERT_HANDSHAKE_FAILURE
 1105   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     pinning-test.badssl.com:443             200
 1106   --      --      --      --                              --      --                              preact-cli.badssl.com:443               CERTIFICATE_VERIFY_FAILED
 1107   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     preloaded-hsts.badssl.com:443           200
 1108   --      --      --      --                              --      --                              rc4-md5.badssl.com:443                  SSLV3_ALERT_HANDSHAKE_FAILURE
 1109   --      --      --      --                              --      --                              rc4.badssl.com:443                      SSLV3_ALERT_HANDSHAKE_FAILURE
 1110   TLSv1.2 3       -424    Oct  8 12:00:00 2021 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     revoked.badssl.com:443                  200
 1111   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     rsa2048.badssl.com:443                  200
 1112   TLSv1.2 3       -630    May  2 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     rsa4096.badssl.com:443                  200
 1113   TLSv1.2 3       -595    Mar 28 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     rsa8192.badssl.com:443                  200
 1114   --      --      --      --                              --      --                              self-signed.badssl.com:443              CERTIFICATE_VERIFY_FAILED
 1115   --      --      --      --                              --      --                              sha1-2016.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1116   --      --      --      --                              --      --                              sha1-2017.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1117   --      --      --      --                              --      --                              sha1-intermediate.badssl.com:443        CERTIFICATE_VERIFY_FAILED
 1118   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     sha256.badssl.com:443                   200
 1119   TLSv1.2 3       -599    Apr  1 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     sha384.badssl.com:443                   200
 1120   TLSv1.2 3       -599    Apr  1 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     sha512.badssl.com:443                   200
 1121   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     spoofed-favicon.badssl.com:443          200
 1122   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    AES256-GCM-SHA384               static-rsa.badssl.com:443               200
 1123   --      --      --      --                              --      --                              subdomain.preloaded-hsts.badssl.com:443 CERTIFICATE_VERIFY_FAILED
 1124   --      --      --      --                              --      --                              superfish.badssl.com:443                CERTIFICATE_VERIFY_FAILED
 1125   --      --      --      --                              --      --                              untrusted-root.badssl.com:443           CERTIFICATE_VERIFY_FAILED
 1126   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        1024    ECDHE-RSA-AES128-GCM-SHA256     upgrade.badssl.com:443                  200
 1127   TLSv1.2 3       -645    May 17 12:00:00 2022 GMT        2048    ECDHE-RSA-AES256-SHA384         very.badssl.com:443                     200
 1128   --      --      --      --                              --      --                              thisis-invalid-url-32443234234.it:443   11001
 1129   TLSv1.2 3       -652    May 24 23:59:59 2022 GMT        2048    ECDHE-RSA-AES256-GCM-SHA384     rubysash.com:443                        200
 1139   --      --      --      --                              --      --                              rubysash.com/gonna404:443               404
Run Time:  5.68 seconds

"""

#https://docs.python.org/3/library/ssl.html
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError

# for dumping our sites dictionary to json
import json

# for getting response codes from header
import urllib.request

# for date calcs
from datetime import datetime

# for proper ctrl + c captures
from signal import signal, SIGINT
from sys import exit

# actual code start time
import time
startTime = time.time()

# for threading
import threading # we want to multi thread this 
from queue import Queue # and have queue management

# read from xlsx
import openpyxl 
from openpyxl import load_workbook

# for sys.exit and argv
import sys

# because we need to know if it's windows or a real os
import os

# for colorized output
from colorama import  init
from colorama import Fore, Back, Style
init()

# to see if it's a xlsx
# for windows: https://github.com/pidydx/libmagicwin64


if os.name == 'nt':
    pass
else:
    # tested on chromebook linux container (ubuntu)
    import magic

# to get the short error codes instead of long
import re


# manual definition if you don't have an xlsx handy
# just set testdata to 1
sites2 = {
1000: 'dsdtestprovider.badssl.com',
1001: 'ecc256.badssl.com',
1002: 'vimeo.com',
1003: 'mozilla.org',
1004: 'europa.eu',
1005: 'medium.com',
1006: 'howsmyssl.com',
1007: '1000-sans.badssl.com',
1008: '10000-sans.badssl.com',
1009: '3des.badssl.com',
1010: 'captive-portal.badssl.com',
1011: 'cbc.badssl.com',
1012: 'client-cert-missing.badssl.com',
1013: 'client.badssl.com',
1014: 'dh-composite.badssl.com',
1015: 'dh-small-subgroup.badssl.com',
1016: 'dh1024.badssl.com',
1017: 'dh2048.badssl.com',
1018: 'dh480.badssl.com',
1019: 'dh512.badssl.com',
1020: 'dsdtestprovider.badssl.com',
1021: 'ecc256.badssl.com',
1022: 'ecc384.badssl.com',
1023: 'edellroot.badssl.com',
1024: 'expired.badssl.com',
1025: 'extended-validation.badssl.com',
1026: 'hsts.badssl.com',
1027: 'https-everywhere.badssl.com',
1028: 'incomplete-chain.badssl.com',
1029: 'invalid-expected-sct.badssl.com',
1030: 'lock-title.badssl.com',
1031: 'en.wikipedia.org',
1032: 'wordpress.org',
1033: 'mitm-software.badssl.com',
1034: 'mixed-favicon.badssl.com',
1035: 'mixed-form.badssl.com',
1036: 'mixed-script.badssl.com',
1037: 'mixed.badssl.com',
1038: 'mozilla-intermediate.badssl.com',
1039: 'mozilla-modern.badssl.com',
1040: 'mozilla-old.badssl.com',
1041: 'no-common-name.badssl.com',
1042: 'no-sct.badssl.com',
1043: 'no-subject.badssl.com',
1044: 'null.badssl.com',
1045: 'pinning-test.badssl.com',
1046: 'preact-cli.badssl.com',
1047: 'preloaded-hsts.badssl.com',
1048: 'rc4-md5.badssl.com',
1049: 'rc4.badssl.com',
1050: 'revoked.badssl.com',
1051: 'rsa2048.badssl.com',
1052: 'rsa4096.badssl.com',
1053: 'rsa8192.badssl.com',
1054: 'self-signed.badssl.com',
1055: 'sha1-2016.badssl.com',
1056: 'sha1-2017.badssl.com',
1057: 'sha1-intermediate.badssl.com',
1058: 'sha256.badssl.com',
1059: 'sha384.badssl.com',
1060: 'sha512.badssl.com',
1061: 'spoofed-favicon.badssl.com',
1062: 'static-rsa.badssl.com',
1063: 'subdomain.preloaded-hsts.badssl.com',
1064: 'superfish.badssl.com',
1065: 'untrusted-root.badssl.com',
1066: 'upgrade.badssl.com',
1067: 'very.badssl.com',
1068: 'webpack-dev-server.badssl.com',
1069: 'wrong.host.badssl.com',
1070: 'self-signed.badssl.com',
1071: 'howsmyssl.com',
1072: '1000-sans.badssl.com',
1073: '10000-sans.badssl.com',
1074: '3des.badssl.com',
1075: 'captive-portal.badssl.com',
1076: 'cbc.badssl.com',
1077: 'client-cert-missing.badssl.com',
1078: 'client.badssl.com',
1079: 'dh-composite.badssl.com',
1080: 'dh-small-subgroup.badssl.com',
1081: 'dh1024.badssl.com',
1082: 'ecc384.badssl.com',
1083: 'edellroot.badssl.com',
1084: 'expired.badssl.com',
1085: 'extended-validation.badssl.com',
1086: 'hsts.badssl.com',
1087: 'https-everywhere.badssl.com',
1088: 'incomplete-chain.badssl.com',
1089: 'invalid-expected-sct.badssl.com',
1090: 'lock-title.badssl.com',
1091: 'webpack-dev-server.badssl.com',
1092: 'wrong.host.badssl.com',
1093: 'mitm-software.badssl.com',
1094: 'mixed-favicon.badssl.com',
1095: 'mixed-form.badssl.com',
1096: 'mixed-script.badssl.com',
1097: 'mixed.badssl.com',
1098: 'mozilla-intermediate.badssl.com',
1099: 'mozilla-modern.badssl.com',
1100: 'mozilla-old.badssl.com',
1101: 'no-common-name.badssl.com',
1102: 'no-sct.badssl.com',
1103: 'no-subject.badssl.com',
1104: 'null.badssl.com',
1105: 'pinning-test.badssl.com',
1106: 'preact-cli.badssl.com',
1107: 'preloaded-hsts.badssl.com',
1108: 'rc4-md5.badssl.com',
1109: 'rc4.badssl.com',
1110: 'revoked.badssl.com',
1111: 'rsa2048.badssl.com',
1112: 'rsa4096.badssl.com',
1113: 'rsa8192.badssl.com',
1114: 'self-signed.badssl.com',
1115: 'sha1-2016.badssl.com',
1116: 'sha1-2017.badssl.com',
1117: 'sha1-intermediate.badssl.com',
1118: 'sha256.badssl.com',
1119: 'sha384.badssl.com',
1120: 'sha512.badssl.com',
1121: 'spoofed-favicon.badssl.com',
1122: 'static-rsa.badssl.com',
1123: 'subdomain.preloaded-hsts.badssl.com',
1124: 'superfish.badssl.com',
1125: 'untrusted-root.badssl.com',
1126: 'upgrade.badssl.com',
1127: 'very.badssl.com',
1128: 'thisis-invalid-url-32443234234.it',
1129: 'rubysash.com',
1139: 'rubysash.com/gonna404'
}


'''
# threader thread pulls worker from queue and processes
'''
def threader():
   while True:
      # gets worker from queue
      worker = q.get()

      # run job with available worker in queue (thread)
      getSSLInfo(worker)
 
      # complete with the job, shut down thread
      q.task_done()

'''
This was supposed to do a clean exit on ctrl+c but instead
It requires a few ctrl+c to work.  It doesnt' error now at least
when ctrl+c is pressed.
'''
def handler(signal_received, frame):
    show_help('SIGINT or CTRL-C detected. Exiting gracefully',1)

'''
Returns status code (ie:  200, 404, 500, 301, etc)
todo: strip off the new lines
'''
def getResponseCode(uri):
    try:
        conn = urllib.request.urlopen(uri)
    except urllib.error.HTTPError as e:
        # Return code error (e.g. 404, 501, ...)
        return(e.code)
    except urllib.error.URLError as e:
        # Not an HTTP-specific error (e.g. connection refused)
        error = str(e.reason)
        err = re.split(r"\s",error)

        if (verbosity):
            return(e.reason)
        else:
            # first, take the chunk we want, then remove last character of string
            short = err[1]
            short = short[:-1]
            return(short)
    else:
        return(200)



'''
Pulls some info from ssl:
expiry, serial, ssl version, bits, cipher, Expire time, domain given (not verified), port checked, response code
expiry is a negative countdown, or in the case of http, just --
'''
def getSSLInfo(kid):
    host    = str(sites[kid])    # expert-marketer.com
    
    # fixme: this was so we could check corp tools for strings
    # and check if apps were up, etc.    Haven't implemented  yet

    #port    = str(sites[kid][1])    # 80
    #proto   = str(sites[kid][3])    # http:// or https://
    #path    = str(sites[kid][4])    # / or /somepath.php
    #text    = str(sites[kid][5])    # text to validate on the site

    # fixme: Everything is https, on port 443 - not real world
    proto = 'https://'
    port = '443'
    path = '/'
    text = 'N/A'

    # It's either going to be http or https
    # if it's http, we just put place holders for now
    # fixme: this logic was for testing other than https, but we aren't doing that now
    checkthis = proto + host + ":" + port + path
    code = getResponseCode(checkthis)
    if (proto == 'http://'):
        nnd[kid] = ['--',"--","--","--","--","--",host + ":" + str(port),str(code)]
    elif (code == 200):
        try:
            # if it's https, this will work, or should work
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                # fixme:  chokes on invalid URL
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # get the ssl/tls info:
                    d = ssock.getpeercert()
                         
                    # dumps a 3 part list: encryption, version, bits
                    cipherinfo = ssock.cipher()

                    # time from input
                    dt1 = datetime.strptime(d['notAfter'], '%b %d %H:%M:%S %Y GMT')

                    # time difference
                    timediff = dt2 - dt1
                    #print(str(timediff.days) + ",", end='')     # -42
                    #print(d['serialNumber'] + ",", end='')      # 56E419412363A9E0E94715A1EC60E545
                    #print(str(d['version']) + ",", end='')      # 3
                    #print(ssock.version() + ",", end='')        # TLSv1.2 (or SSLv2, SSLv3, TLSv1, TLSv1.1)
                    #print(str(cipherinfo[2]) + ",", end='')     # 256 (x8 for 2048 RSA key)
                    #print(cipherinfo[0] + ",", end='')          # ECDHE-RSA-AES256-GCM-SHA384
                    #print(d['notAfter'] + ",", end='')          # May 24 23:59:59 2020 GMT
                    #print(host + ":" + str(port) + ",", end='') # rubysash:443
                    nd[kid] = [ssock.version(),d['version'],str(timediff.days),d['notAfter'],cipherinfo[2],cipherinfo[0],host + ":" + str(port),str(code)]

        except:
            # whoops, it's probably not https, but we did get a 200 code.  Do something better here
            # this branch only happened when I was debugging code error, not with working code
            nd[kid] = ['--',"--","--","--","--","--",host + ":" + str(port),str(code)]
    else:
        # this branch is the normal failsafe if we can't get a good handshake
        nd[kid] = ['--',"--","--","--","--","--",host + ":" + str(port),str(code)]


"""
Show help message from input
Include example
colorize it bright yellow, reset colors
logic to stop script depending on message type
"""
def show_help(msg,andquit):
    print(Style.BRIGHT, Fore.YELLOW, msg, Style.RESET_ALL)

    if(andquit):
        print("Example: python3 " + sys.argv[0] + " sites.xlsx Sheet1 2")
        print(Style.DIM,"(to print the 2nd column in the sites.xlsx Sheet1 workbook)",Style.RESET_ALL)
        sys.exit()


"""
opens a spreadsheet
reads a column
skips first row
returns rest as list
"""
def get_url_list(file,sheet,wanted):
    # this could be changed to any number
    # it sorts up to 9999 items in same entry order
    # even though it multithreads the process
    idx = 1000

    # does file we provided as input even exist?
    try:
        with open(file) as f:
            # Do something with the file, continue
            pass
    except FileNotFoundError:
        # Error and die
        show_help("Sorry, we cannot find or open the file specified",1)

    # is it really an xls file? (file magic only work on !nt)
    if os.name == 'nt':
        pass
    else:
        detected = magic.detect_from_filename(file)
        if(verbosity):
            print('Detected MIME type: {}'.format(detected.mime_type))
            print('Detected encoding: {}'.format(detected.encoding))
            print('Detected file type name: {}'.format(detected.name))

        if(detected.name == 'Microsoft Excel 2007+'):
            # yes it's an excel file
            pass
        else:
            # error and die
            show_help("Sorry, we can only process xlsx, xlsm, xltx or xltm files",1)

    # open the file
    wb = openpyxl.load_workbook(file)

    # open the sheet of this workbook
    ws = wb[sheet]

    # scoping look
    sites = {}

    # track the starting row
    rowx = 0

    # loop over each row
    for row in ws.rows:

        # reset column counter
        col = 0

        # loop over each column
        for cell in row:

            # update column counter
            col = col + 1

            # if it's the one we want, and not a header
            if(col == wanted) and (rowx > 0):
                sites[idx] = cell.value
                idx = idx + 1

        # update our tracking row so we know which one we are one
        rowx = rowx + 1

    # return the dictionary
    return(sites)



# verify user gave us info or educate and die
if (len(sys.argv) < 4):
    show_help("No file, sheet or column specified",1)

# get info from user
file = sys.argv[1]
sheet = sys.argv[2]
wanted = int(sys.argv[3])

# get the list of sites from input file
sites = get_url_list(file,sheet,wanted)

# but if we are using test data, ignore input and use tests
if(testdata == 1):
    sites = sites2.copy()
    show_help("using test data!!!  xlsx and choices are ignored",0)


# get the current time for expiry time calculations
# current time is only needed once at start
now = datetime.now()
dt2 = datetime.strptime(now.strftime("%Y-%m-%d %H:%M:%S"), '%Y-%m-%d %H:%M:%S')


# Tell Python to run the handler() function when SIGINT is recieved
# run the program inside a ctrl + c check
signal(SIGINT, handler)

# we have to load this guy up quickly then print out when it's complete
# the with print_lock slows things down too much
nd = {}

# loop over our dictionary of lists
show_help('SSL Test, V' + str(version) + ' is Running (' + str(thread_max) + ' threads) Press CTRL+C to exit.',0)
#fixme: do some padding based on max lengths
print("ID   \tTLS\tSSL\tDAYS\tEXPIRE DATE              \tLENGTH\tCIPHER TTYPE                \tURL:PORT                          \tSTATUS",Style.RESET_ALL)
while True:

    # create queue and threader      
    q = Queue()
    for x in range(thread_max):
       # thread id
       t = threading.Thread(target = threader)
       
       # classifying as a daemon, so they will die when the main dies
       t.daemon = True
       
       # begins, must come after daemon definition
       t.start()
     
    # this is the range or variable passed to the worker pool
    # we are loading up the thread pool here
    # work is done in the threader, not here
    for worker in (sites.keys()):
        q.put(worker)
     
    # wait until thrad terminates, then reassemble
    q.join()        

    # now that we built this dictionary threaded, spit it out in single thread
    # this allows a sort and seemed the fastest way instead of print locking
    # todo:  I'm sure this isn't the pythonic way to make a CSV!
    for kid in sorted (nd.keys()):
        
        bit_strength = str(nd[kid][4])
        if (bit_strength == '--'):
            pass
        else:
            bit_strength = str(nd[kid][4] * 8)

        # fixme: this is some ghetto padding
        time_pad = (27 - len(nd[kid][3])) * " "
        cipher_pad = (30 - len(nd[kid][5])) * " "
        url_pad = (35 - len(nd[kid][6])) * " "

        code = nd[kid][7]

        # fixme: I don't really like multiline pep8 anyway
        print(Style.RESET_ALL,end="")
        if (code == '200'):
            print(Fore.GREEN,str(kid) + "\t" + str(nd[kid][0]) + "\t" + str(nd[kid][1]) + "\t" + str(nd[kid][2]) + "\t" + str(nd[kid][3]) + time_pad + "\t" + bit_strength + "\t" + str(nd[kid][5]) + cipher_pad + "\t" + str(nd[kid][6]) + url_pad + "\t" + str(code),Style.RESET_ALL)
        else:
            print(Style.BRIGHT,end="")
            print(Fore.RED,str(kid) + "\t" + str(nd[kid][0]) + "\t" + str(nd[kid][1]) + "\t" + str(nd[kid][2]) + "\t" + str(nd[kid][3]) + time_pad + "\t" + bit_strength + "\t" + str(nd[kid][5]) + cipher_pad + "\t" + str(nd[kid][6]) + url_pad + "\t" + str(code),Style.RESET_ALL)
 

    # ok, give us a final time report
    runtime = float("%0.2f" % (time.time() - startTime))
    print("Run Time: ", runtime, "seconds")

    # end of ctrl + c check too
    exit(0)
