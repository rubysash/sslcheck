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

'''
Sample output
Running.  Press CTRL+C to exit.
-78,03837BA1163BF4B49D6B68695FAA80BCA643,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:10 2020 GMT,emailmarketinglabs.com:443,200
1,0,0,0,0,expert-marketer.com:80,200
-62,0481890D24042F80DD7A9E7174A516FDB5A4,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 11 02:56:25 2020 GMT,12holeocarina.com:443,200
-79,0371F8919C3BDEF66F3EB4F8922C3C49D68C,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 28 04:51:29 2020 GMT,6holeocarina.com:443,200
-63,03F9AD409D15FA024170E80A7FEB06F22B13,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 12 00:57:08 2020 GMT,aquaponics-system.com:443,200
-78,034853BD9C3A7FE151AC9B4FDF3B895223A4,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:42:36 2020 GMT,ar15-scope.com:443,200
-78,03181AE8506C1821F135ECA2A39BA9B2384E,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:42:42 2020 GMT,ar15-scopes.com:443,200
-78,0352DA3D15E29184990A4F6BADDD2AE47386,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:42:47 2020 GMT,assistedlivingnear.me:443,200
-78,03F2489162DB0A8413A9D25320E216AA7484,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:42:53 2020 GMT,bakersfieldcleaningservices.com:443,200
-83,035F090DC962E69D83B246D5BCE06E041B86,3,256,ECDHE-RSA-AES256-GCM-SHA384,May  2 01:30:08 2020 GMT,centralpilotcar.com:443,200
-78,034810B288A54DD2D6739B04534D205BE3D7,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:42:59 2020 GMT,dependablenursestaffing.com:443,200
-63,03368AABC6DA80CCBE822928D961A84DB293,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 11 22:09:09 2020 GMT,digitalcrunch.com:443,200
-78,0330ADFED15EFCE86AB22F23827C8E83DE3A,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:05 2020 GMT,drsavoy.com:443,200
-78,036E7E1EC5D8902CFEA54E50CB44D8006F62,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:17 2020 GMT,followupemails.com:443,200
-78,03D11C26E876018E6A8B8BA9976F6AFDB2D2,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:22 2020 GMT,gentlehandstherapy.com:443,200
-87,036EA22ADC70090A6B3D897AB199E11C81CF,3,256,ECDHE-RSA-AES256-GCM-SHA384,May  5 22:33:15 2020 GMT,hollowedstone.com:443,200
-78,04BB5138F90A5BF8C360D14833A092E313B9,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:29 2020 GMT,how-to-build-credit.com:443,200
-78,0302D7C6B8FD8845901D9E927740E3933E71,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:35 2020 GMT,how-to-establish-credit.com:443,200
-78,040688D4D454A454654BAF6AA514386B1CC8,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:41 2020 GMT,how-to-get-credit.com:443,200
-78,030DD049CA219292F168E4035D8BD71ABE66,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:46 2020 GMT,localmasterminds.com:443,200
-78,0497F980343BD312630B48C269F915FDA4C2,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:52 2020 GMT,ocarina-sheetmusic.com:443,200
-78,03D54F57264C5CA99606FA08057F74BC0138,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:59 2020 GMT,ocarina-songbook.com:443,200
-78,03815D16C7181167C775DCFD3265D6A5BA3C,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:44:05 2020 GMT,ocarina-songs.com:443,200
-78,03752654F4BC40424094C6C34B7E4AE8398E,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:44:11 2020 GMT,overnightcashbandit.com:443,200
-78,041B42ED653721FF1E91A2ED6570D77812C5,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:44:17 2020 GMT,phoenixseoservices.com:443,200
-79,04EFA00D4BC5B812C0879AE0DBC8E245DBF1,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 28 04:51:35 2020 GMT,poynterscifres.com:443,200
-78,03CE736435CD7F982446D5A41A04D6B715B0,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:44:22 2020 GMT,redmountainadmin.com:443,200
-106,56E419412363A9E0E94715A1EC60E545,3,256,ECDHE-RSA-AES256-GCM-SHA384,May 24 23:59:59 2020 GMT,rubysash.com:443,200
-32,03A9FBFC1D7B8F5A96AEEDCBDC2EAAF1C295,3,256,ECDHE-RSA-AES256-GCM-SHA384,Mar 11 20:34:20 2020 GMT,scstormshelters.com:443,200
-42,033AD122EF33D88A6197CCA86241FCC4BF9C,3,256,ECDHE-RSA-AES256-GCM-SHA384,Mar 22 01:59:22 2020 GMT,sellyourhomefastonline.com:443,200
-78,0409CFFC0BB16A4D7A20CE295A8A660716E4,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:44:28 2020 GMT,seniorassistedlivingcare.com:443,200
-78,0483AB37F2B7AFB96456B22F66E453D0CA3A,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:44:34 2020 GMT,seocompanyphoenix.com:443,200
-62,04FAD4AE27FB2A85F70FBE1DBE6EC4A4F5B0,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 10 22:40:17 2020 GMT,vestedportfolio.com:443,200
-62,0326C6BE98DB007743C781A9A5A1EC040033,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 10 22:32:51 2020 GMT,workerboost.com:443,200
Run Time:  42.77 seconds
'''


'''
todo:
ssl handshake measuremnts
test for ssl vulnerabilities
tcp handshake response
ping response
page load time
'''


'''
How to create sample data
# our database of sites, a dictionary of lists
# As I want to test the domain, expected response code, 
#protocol, URI and arbitrary text string, I've chosen
# the following:    The dictionary key is for my 
# own internal book keeping, but could of been anything
# like a domain+URI, etc.    

sites = {
    1001:["6holeocarina.com",443,200,"https://","/","N/A"],
    1002:["aquaponics-system.com",443,200,"https://","/","N/A"],
    1003:["ar15-scope.com",443,200,"https://","/","N/A"],
}

print("Writing 'sites.json' file...")
with open ('sites.json', 'w') as outfile:
    json.dump(sites, outfile, indent=2)

# after I write out my sample, I can write the rest or manually add
# todo: create function to add sites to data
'''


# get the current time for expiry time calculations
# current time is only needed once at start
now = datetime.now()
dt2 = datetime.strptime(now.strftime("%Y-%m-%d %H:%M:%S"), '%Y-%m-%d %H:%M:%S')


'''
This was supposed to do a clean exit on ctrl+c but instead
It requires a few ctrl+c to work.  It doesnt' error now at least
when ctrl+c is pressed.
'''
def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)

'''
Just an http status code return from uri input
todo: strip off the new lines
'''
def getResponseCode(uri):
    conn = urllib.request.urlopen(uri)
    return conn.getcode()

'''
Pulls some info from ssl:
expiry, serial, ssl version, bits, cipher, Expire time, domain given (not verified), port checked, response code
expiry is a negative countdown, or in the case of http, just a 1 (see below)

-79,03837BA1163BF4B49D6B68695FAA80BCA643,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:10 2020 GMT,emailmarketinglabs.com:443,200
'''
def getSSLInfo(checkthis, host, port):
    try:
        # if it's https, this will work, or should work
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # get the ssl/tls info:
                d = ssock.getpeercert()
                  
                # dumps a 3 part list: encryption, version, bits
                cipherinfo = ssock.cipher()

                # time from input
                dt1 = datetime.strptime(d['notAfter'], '%b %d %H:%M:%S %Y GMT')

                # time difference
                timediff = dt2 - dt1
                print(str(timediff.days) + ",", end='')

                print(d['serialNumber'] + ",", end='')      # 56E419412363A9E0E94715A1EC60E545
                print(ssock.version() + ",", end='')        # TLSv1.2 (or SSLv2, SSLv3, TLSv1, TLSv1.1)
                print(str(d['version']) + ",", end='')      # 3
                print(str(cipherinfo[2]) + ",", end='')     # 256
                print(cipherinfo[0] + ",", end='')          # ECDHE-RSA-AES256-GCM-SHA384
                print(d['notAfter'] + ",", end='')          # May 24 23:59:59 2020 GMT
                print(host + ":" + str(port) + ",", end='') # rubysash:443
                print(getResponseCode(checkthis))
    except:
        # whoops, it's probably not https.  Do something better here
        print("1,0,0,0,0,", end='')
        print(host + ":" + str(port) + "," + str(getResponseCode(checkthis)))


# loop over our dictionary of lists
if __name__ == '__main__':
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)

    # preload from sites.json file instead of data in script
    with open('sites.json', 'r') as infile:
        # put it into a dictionary called "data"
        sites = json.load(infile)
    
    # run the program inside a ctrl + c check
    print('Running.  Press CTRL+C to exit.')
    while True:

        # k is the key for sites
        # sk is the inner list, accessed by index    
        for k,sk in sites.items():
            host    = str(sk[0])    # expert-marketer.com
            port    = str(sk[1])    # 80
            proto   = str(sk[3])    # http:// or https://
            path    = str(sk[4])    # / or /somepath.php
            text    = str(sk[5])    # text to validate on the site

            # It's either going to be http or https, though what should default be?
            checkthis = proto + host + ":" + port + path
            if (proto == 'http://'):
                print("1,0,0,0,0,", end='')
                print(host + ":" + str(port) + "," + str(getResponseCode(checkthis)))
            else:
                getSSLInfo(checkthis,host,port)
        
        
        # ok, give us a final time report
        runtime = float("%0.2f" % (time.time() - startTime))
        print("Run Time: ", runtime, "seconds")

        # end of ctrl + c check too
        exit(0)





