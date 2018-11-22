import os
import shutil
from securep2p227 import keys as sp

# delete the existing key
if os.path.isdir("test-data/test1"):
	shutil.rmtree("test-data/test1")

# create a new key with test fake data
key = sp.genKey("test-data", "test1", "Dr. McCoy", "NCC-1701 USS Enterprise")

# create a host object to connect to specify the server name
host = sp.Host("securep2p.fivebillionmph.com")

# register our key to the host
key.register(host)

# create a new session object with the host and key
session = sp.Session(host, key)

# start the session on the server
session.startSession(8080)

# get the active sessions
active_sessions = session.getActiveSessions()

# get my signatures (not working yet)
my_signatures = session.getSignatures()
print(my_signatures)
