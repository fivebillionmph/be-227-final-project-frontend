import os
import shutil
from securep2p227 import keys as sp

if os.path.isdir("test-data/test1"):
	shutil.rmtree("test-data/test1")

key = sp.genKey("test-data", "test1", "Dr. McCoy", "NCC-1701 USS Enterprise")

host = sp.Host("securep2p.fivebillionmph.com")

key.register(host)

session = sp.Session(host, key)

session.startSession(8080)

active_sessions = session.getActiveSessions()
my_signatures = session.getSignatures()

print(my_signatures)
