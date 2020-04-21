'''
SSL Tester

it's incomplete for ALL that I want it to do, 
but it does test ssls as-is and is another part
of my "learn python" journey

Main purpose was to verify my cert bot expiry times so I could 
have plenty of time to renew them.  I'm now thinking of what I want
to look at across the board on all of my servers.  
Ideas welcome!

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
'''

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

import threading # we want to multi thread this 
from queue import Queue # and have queue management

'''
Sample output (single threaded 40~ sites)
Running.  Press CTRL+C to exit.
-78,03837BA1163BF4B49D6B68695FAA80BCA643,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 27 07:43:10 2020 GMT,emailmarketinglabs.com:443,200
1,0,0,0,0,expert-marketer.com:80,200
...
-62,0326C6BE98DB007743C781A9A5A1EC040033,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 10 22:32:51 2020 GMT,workerboost.com:443,200
Run Time:  42.77 seconds

Sample output (multi threaded 40~ sites)
Running.  Press CTRL+C to exit.
1000,-62,0481890D24042F80DD7A9E7174A516FDB5A4,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 11 02:56:25 2020 GMT,12holeocarina.com:443,200
...
1041,-62,0326C6BE98DB007743C781A9A5A1EC040033,3,256,ECDHE-RSA-AES256-GCM-SHA384,Apr 10 22:32:51 2020 GMT,workerboost.com:443,200
Run Time:  10.23 seconds (DNS fresh)
Run Time:  4.03 seconds (DNS cached)

How to create sample data
# our database of sites, a dictionary of lists
# As I want to test the domain, expected response code, 
#protocol, URI and arbitrary text string, I've chosen
# the following:    The dictionary key is for my 
# own internal book keeping, but could of been anything
# like a domain+URI, etc.    

# here is a sample of sites to get started
# I used some google sheets concatenation to build up the data,
# then pasted all sites to create my initial json, but you can just
# type a few like I did:

sites = {
  "1000": ["howsmyssl.com",443,200,"https://","/","N/A"],
  "1001": ["www.google.com",443,200,"https://","/","N/A"],
  "1002": ["wellsfargo.com",443,200,"https://","/","N/A"],
  "1003": ["rubysash.com",443,200,"https://","/","N/A" ]
}

# write it out to json so I can just run it from a json load later
print("Writing 'sites.json' file...")
with open ('sites.json', 'w') as outfile:
    json.dump(sites, outfile, indent=2)

# after I write out my sample, I can write the rest or manually add
# todo: create function to add sites to data easily
'''





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
def getSSLInfo(kid):
    host    = str(sites[kid][0])    # expert-marketer.com
    port    = str(sites[kid][1])    # 80
    proto   = str(sites[kid][3])    # http:// or https://
    path    = str(sites[kid][4])    # / or /somepath.php
    text    = str(sites[kid][5])    # text to validate on the site

    # It's either going to be http or https
    # if it's http, we just put place holders for now
    checkthis = proto + host + ":" + port + path
    if (proto == 'http://'):
        nd[kid] = [1,0,0,0,0,0,host + ":" + str(port),str(getResponseCode(checkthis))]
    else:
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
                    #print(str(timediff.days) + ",", end='')
                    #print(d['serialNumber'] + ",", end='')      # 56E419412363A9E0E94715A1EC60E545
                    #print(str(d['version']) + ",", end='')      # 3
                    #print(ssock.version() + ",", end='')         # TLSv1.2 (or SSLv2, SSLv3, TLSv1, TLSv1.1)
                    #print(str(cipherinfo[2]) + ",", end='')     # 256 (x8 for 2048 RSA key)
                    #print(cipherinfo[0] + ",", end='')          # ECDHE-RSA-AES256-GCM-SHA384
                    #print(d['notAfter'] + ",", end='')          # May 24 23:59:59 2020 GMT
                    #print(host + ":" + str(port) + ",", end='') # rubysash:443
                    #print(getResponseCode(checkthis))
                    nd[kid] = [ssock.version(),d['version'],str(timediff.days),d['notAfter'],cipherinfo[2],cipherinfo[0],host + ":" + str(port),str(getResponseCode(checkthis))]

        except:
            # whoops, it's probably not https.  Do something better here
            nd[kid] = [1,0,0,0,0,0,host + ":" + str(port),str(getResponseCode(checkthis))]


# get the current time for expiry time calculations
# current time is only needed once at start
now = datetime.now()
dt2 = datetime.strptime(now.strftime("%Y-%m-%d %H:%M:%S"), '%Y-%m-%d %H:%M:%S')

# loop over our dictionary of lists
# Tell Python to run the handler() function when SIGINT is recieved
signal(SIGINT, handler)

# preload from sites.json file instead of data in script
with open('sites.json', 'r') as infile:
    # put it into a dictionary called "data"
    sites = json.load(infile)

# we have to load this guy up quickly then print out when it's complete
# the with print_lock slows things down too much
nd = {}

# run the program inside a ctrl + c check
print('Running.  Press CTRL+C to exit.')
while True:

    # create queue and threader      
    q = Queue()
    for x in range(200):
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
        print(str(kid) + "\t" + str(nd[kid][0]) + "\t" + str(nd[kid][1]) + "\t" + str(nd[kid][2]) + "\t" + str(nd[kid][3]) + "\t" + str(nd[kid][4]) + "\t" + str(nd[kid][5]) + "\t" + str(nd[kid][6]) + "\t" + str(nd[kid][7]))
            
    # ok, give us a final time report
    runtime = float("%0.2f" % (time.time() - startTime))
    print("Run Time: ", runtime, "seconds")

    # end of ctrl + c check too
    exit(0)
