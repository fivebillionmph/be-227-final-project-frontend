import os
import shutil
import glob
import datetime
from securep2p227 import keys as sp

# delete the existing key
for path in glob.glob("test-data/*"):
	shutil.rmtree(path)

# create a host object to connect to specify the server name
host = sp.Host("securep2p.fivebillionmph.com")

# create a new key with test fake data
key1 = sp.genKey("test-data", "test1", "Dr. Leonard McCoy", "NCC-1701 USS Enterprise")

# register our key to the host
key1.register(host)

# create a new session object with the host and key
session1 = sp.Session(host, key1)

# start the session on the server
session1.startSession(8080)

# create a second key and session
key2 = sp.genKey("test-data", "test2", "Dr. Beverly Crusher", "NCC-1701-D USS Enterprise")
key2.register(host)
session2 = sp.Session(host, key2)
session2.startSession(8081)

# sign a key
now = datetime.datetime.now()
tomorrow = now + datetime.timedelta(days=1)
session1.signKeyAndSubmit(key2._public_key, now, tomorrow)

# get the active sessions
active_sessions = session1.getActiveSessions()

# get my signatures (not working yet)
my_signatures = session2.getSignatures()
print(my_signatures)
