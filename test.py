import json
import os
import shutil
import glob
import datetime
from securep2p227 import keys as sp
import sys

# delete the existing key
for path in glob.glob("test-data/keys/*"):
	shutil.rmtree(path)
for path in glob.glob("test-data/permissions/*"):
	os.remove(path)

# create a host object to connect to specify the server name
host = sp.Host("securep2p.fivebillionmph.com")

# create a new key with test fake data
key1 = sp.genKey("test-data/keys", "test1", "Dr. Leonard McCoy", "NCC-1701 USS Enterprise")

# key fingerprint
print(key1.publicKeyFingerprint())
print(sp.prettyFingerprint(key1.publicKeyFingerprint()))

# register our key to the host
key1.register(host)

# create a new session object with the host and key
session1 = sp.Session(host, key1)

# start the session on the server
session1.startSession(8080)

# create a second key and session
key2 = sp.genKey("test-data/keys", "test2", "Dr. Beverly Crusher", "NCC-1701-D USS Enterprise")
key2.register(host)
session2 = sp.Session(host, key2)
session2.startSession(8081)

# create a third session
key3 = sp.genKey("test-data/keys", "test3", "Dr. Alexander Siddig", "Deep Space Nine")
key3.register(host)
session3 = sp.Session(host, key3)
session3.startSession(8082)

# create a fouth session
key4 = sp.genKey("test-data/keys", "test4", "Dr. Evil", "Starbucks")
key4.register(host)
session4 = sp.Session(host, key4)
session4.startSession(8083)

# search keys
enterprise_keys = sp.searchKeys(host, "enterprise")
all_keys = sp.searchKeys(host)

# sign a key
now = datetime.datetime.now()
tomorrow = now + datetime.timedelta(days=1)
key1.signKeyAndSubmit(key2._public_key, host, now, tomorrow)

# get the active sessions
active_sessions_all = sp.searchSessions(host)
active_sessions_ds9 = sp.searchSessions(host, "deep space")
print("all sessions:", len(active_sessions_all["sessions"]))
print("deep space nine sessions:", len(active_sessions_ds9["sessions"]))

# get my signatures
my_signatures = session2.getSignatures()

permission3 = sp.Permission("test-data/permissions", "ds9-files")
permission3.addAuthorizedKey(sp.publicKeyToPemString(key1._public_key), "Dr. McCoy", "USS Enterprise")
# print(permission3.getAuthorizedKeys())
print("Dr. McCoy", permission3.authorize(sp.publicKeyToPemString(key1._public_key), None, None, None, "Multiple Patient Identifiers (C-CDAR2.1).xml"))
print("Dr. Crusher", permission3.authorize(sp.publicKeyToPemString(key2._public_key), my_signatures["signatures"][0]["signature"], json.loads(my_signatures["signatures"][0]["message"]), my_signatures["signatures"][0]["signer"]["public_key"], "Multiple Patient Identifiers (C-CDAR2.1).xml"))
print("Dr. Evil", permission3.authorize(sp.publicKeyToPemString(key4._public_key), my_signatures["signatures"][0]["signature"], json.loads(my_signatures["signatures"][0]["message"]), my_signatures["signatures"][0]["signer"]["public_key"], "Multiple Patient Identifiers (C-CDAR2.1).xml"))

session3.stopSession()
active_sessions_ds9 = sp.searchSessions(host, "deep space")
print("deep space nine sessions after ending:", len(active_sessions_ds9["sessions"]))

# send encrypted message
encrypted_message = sp.encryptMessageB64(key1._public_key, "Dodgers win WS 2019")
print(encrypted_message)
decrypted_message = key1.decryptMessageB64(encrypted_message)
print(decrypted_message)

# sign key for specific patient
key1.signKeyAndSubmitCDAPatientID(key2._public_key, host, now, tomorrow, "1.3.6.1.4.1.1234.13.20.9999.1.3.7.3 - 2345")
my_signatures = session2.getSignatures()
print("verify patient previouse name", permission3.authorize(sp.publicKeyToPemString(key2._public_key), my_signatures["signatures"][1]["signature"], json.loads(my_signatures["signatures"][1]["message"]), my_signatures["signatures"][1]["signer"]["public_key"], "test-data/Patient Previous Name(C-CDA2.1).xml"))
print("verify patient mutiple identifiers", permission3.authorize(sp.publicKeyToPemString(key2._public_key), my_signatures["signatures"][1]["signature"], json.loads(my_signatures["signatures"][1]["message"]), my_signatures["signatures"][1]["signer"]["public_key"], "test-data/Multiple Patient Identifiers (C-CDAR2.1).xml"))


print(json.dumps(key1._private_key.save_pkcs1().decode("utf-8"), indent=4).replace("\\n", "\n"))
print(json.dumps(json.loads(my_signatures["signatures"][1]["message"]), indent=4).replace("\\n", "\n    "))
sig = my_signatures["signatures"][1]["signature"]
for i in range(len(sig)):
	sys.stdout.write(sig[i])
	if i != 0 and i % 40 == 0:
		sys.stdout.write("\n")
sys.stdout.write("\n")

print(permission3.getAuthorizedKeys())
permission3.deleteAuthorizedKeysByName("Dr. McCoy")
print(permission3.getAuthorizedKeys())
