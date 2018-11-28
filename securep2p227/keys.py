import time
import random
import os
import rsa
import json
import requests
import base64
import hashlib
import bcrypt
import re
import xml.etree.ElementTree as ET

_PRIVATE_KEY_FILE_NAME = "private-key"
_PUBLIC_KEY_FILE_NAME = "public-key"
_INFO_FILE_NAME = "info"

def getKey(key_dir, name):
	"""Gets an existing key

	Parameters
	----------
	key_dir : str
		The directory where all keys are stored.  This should be the same for all keys
	name : str
		The name of the key, this needs to be unique for each key
	"""
	if not os.path.isdir(os.path.join(key_dir, name)):
		raise Exception("key directory does not exist")

	private_key_file = os.path.join(key_dir, name, _PRIVATE_KEY_FILE_NAME)
	public_key_file = os.path.join(key_dir, name, _PUBLIC_KEY_FILE_NAME)
	info_file = os.path.join(key_dir, name, _INFO_FILE_NAME)

	if not os.path.isfile(private_key_file) or not os.path.isfile(public_key_file) or not os.path.isfile(info_file):
		raise Exception("private or public key missing")

	with open(private_key_file, mode="rb") as f:
		keydata = f.read()
		private_key = rsa.PrivateKey.load_pkcs1(keydata)

	with open(public_key_file, mode="rb") as f:
		keydata = f.read()
		public_key = rsa.PublicKey.load_pkcs1(keydata)

	with open(info_file, mode="r") as f:
		infodata_raw = f.read()
		infodata = json.loads(infodata_raw)
		user_name = infodata["name"]
		user_organization = infodata["organization"]

	return Key(private_key, public_key, os.path.join(key_dir, name), user_name, user_organization)

def genKey(key_dir, name, user_name, user_organization):
	"""Creates a new key

	Parameters
	----------
	key_dir : str
		The directory where all keys are stored.  This should be the same for all keys
	name : str
		The name of the key, this needs to be unique for each key
	user_name : str
	user_organization : str
	"""
	dir_path = os.path.join(key_dir, name)
	os.mkdir(dir_path)
	(public_key, private_key) = rsa.newkeys(2048)
	info_data = {
		"name": user_name,
		"organization": user_organization,
	}

	private_key_file = os.path.join(dir_path, _PRIVATE_KEY_FILE_NAME)
	public_key_file = os.path.join(dir_path, _PUBLIC_KEY_FILE_NAME)
	info_file = os.path.join(dir_path, _INFO_FILE_NAME)

	with open(private_key_file, mode="wb") as f:
		f.write(private_key.save_pkcs1())

	with open(public_key_file, mode="wb") as f:
		f.write(public_key.save_pkcs1())

	with open(info_file, mode="w") as f:
		f.write(json.dumps(info_data))

	return Key(private_key, public_key, dir_path, user_name, user_organization)

def publicKeyToPemString(public_key):
	return public_key.save_pkcs1().decode("utf-8")

def pemStringToPublicKey(pem_string):
	return rsa.PublicKey.load_pkcs1(pem_string.encode("utf-8"))

def signatureMessageToString(message):
	return message["public_key"] + str(message["start_time"]) + str(message["end_time"]) + message["check_server"] + message["message_key"] + message["modifiers"]

def searchKeys(host, query = None):
	url, method = host.getSearchKeysURL()
	if query is not None:
		url += "?q=" + query
	response = requests.request(method, url)
	if response.ok:
		return response.json()
	return None

def searchSessions(host, query = None):
	url, method = host.getSessionsURL()
	if query is not None:
		url += "?q=" + query
	response = requests.request(method, url)
	if not response.ok:
		raise Exception(response.text)
	return response.json()

def publicKeyFingerprint(public_key):
	public_key_pem = publicKeyToPemString(public_key)
	m = hashlib.md5()
	m.update(public_key_pem.encode("utf-8"))
	h = m.hexdigest().lower()
	return h

def prettyFingerprint(fingerprint):
	new_fingerprint = ""
	for i in range(len(fingerprint)):
		if i != 0 and i % 2 == 0:
			new_fingerprint += " : "
		new_fingerprint += fingerprint[i]
	return new_fingerprint

def encryptMessageB64(public_key, message):
	return base64.b64encode(rsa.encrypt(message.encode("utf-8"), public_key)).decode("utf-8")

def parseModifiers(modifiers_string):
	# only match CAD ID for now
	m = re.match(r"CDA\(ID=(.*)\)", modifiers_string)
	if len(m.groups()) > 0:
		return {
			"cda": {
				"encrypted_id": m.group(1)
			}
		}
	return None

class Host:
	"""A class for the key host and generating urls
	"""
	protocol = "http"

	def __init__(self, fqdn):
		"""
		Parameters
		----------
		fqdn : str
			The host that will be connected to for sessions and signed keys (just use securep2p.fivebillionmph.com)
		"""
		self._fqdn = fqdn

	def registerURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/register", "PUT")

	def registerChallengeURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/register/challenge", "PUT")

	def startSessionURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/session", "POST")

	def stopSessionURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/session", "DELETE")

	def startSessionChallengeURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/session/challenge", "PUT")

	def getSessionsURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/sessions", "GET")

	def getSignaturesURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/signatures", "GET")

	def getSignURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/sign", "POST")

	def getSearchKeysURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/keys", "GET")

class Key:
	"""A class for holding the public and private key
	"""
	def __init__(self, private_key, public_key, dir_path, name, organization):
		self._private_key = private_key
		self._public_key = public_key
		self._dir_path = dir_path
		self._name = name
		self._organization = organization

	def publicKeyString(self):
		return publicKeyToPemString(self._public_key)

	def register(self, host):
		url, method = host.registerURL()
		req_data = {
			"public_key": self.publicKeyString(),
		}
		response = requests.request(method, url, json=req_data)
		if not response.ok:
			raise Exception(response.text)
		rjson = response.json()
		crypt_message = base64.b64decode(rjson["message"])
		message = rsa.decrypt(crypt_message, self._private_key)
		signature = rsa.sign(message, self._private_key, "SHA-256")
		signed_message = base64.b64encode(signature).decode("utf-8")

		url2, method2 = host.registerChallengeURL()
		req_data2 = {
			"signature": signed_message,
			"index": rjson["index"],
			"name": self._name,
			"organization": self._organization,
		}
		response2 = requests.request(method2, url2, json=req_data2)
		if not response2.ok:
			raise Exception(response2.text)

	def startSession(self, host, port):
		url, method = host.startSessionURL()
		req_data = {
			"public_key": self.publicKeyString(),
		}
		response = requests.request(method, url, json=req_data)
		if not response.ok:
			raise Exception(response.text)
		rjson = response.json()
		crypt_message = base64.b64decode(rjson["message"])
		message = rsa.decrypt(crypt_message, self._private_key)
		signature = rsa.sign(message, self._private_key, "SHA-256")
		signed_message = base64.b64encode(signature).decode("utf-8")

		url2, method2 = host.startSessionChallengeURL()
		req_data2 = {
			"signature": signed_message,
			"index": rjson["index"],
			"port": port,
		}
		response2 = requests.request(method2, url2, json=req_data2)
		if not response2.ok:
			raise Exception(response2.text)
		rjson2 = response2.json()

		return rjson2["session_id"]

	def signKeyAndSubmit(self, public_key, host, start_time, end_time, modifiers = ""):
		start_unix = int(time.mktime(start_time.timetuple()))
		end_unix = int(time.mktime(end_time.timetuple()))
		message_key = str(random.randint(0, 1000000000))
		message = {
			"public_key": publicKeyToPemString(public_key),
			"start_time": start_unix,
			"end_time": end_unix,
			"check_server": host._fqdn,
			"message_key": message_key,
			"modifiers": modifiers,
		}
		message_str = signatureMessageToString(message)
		signature = rsa.sign(message_str.encode("utf-8"), self._private_key, "SHA-256")
		signature_base64 = base64.b64encode(signature).decode("utf-8")
		url, method = host.getSignURL()
		req_data = {
			"signature": signature_base64,
			"message": message,
			"signee_public_key": publicKeyToPemString(public_key),
			"signer_public_key": publicKeyToPemString(self._public_key),
		}
		response = requests.request(method, url, json=req_data)
		if not response.ok:
			raise Exception(response.text)

	def signKeyAndSubmitCDAPatientID(self, public_key, host, start_time, end_time, patient_id):
		encrypted_id = bcrypt.hashpw(patient_id.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
		modifiers = "CDA(ID=" + encrypted_id + ")"
		self.signKeyAndSubmit(public_key, host, start_time, end_time, modifiers)

	def encrypt(self, public_key_string, message):
		public_key = pemStringToPublicKey(public_key_string)
		return rsa.encrypt(message.encode("utf-8"), public_key)

	def decrypt(self, crypt_message):
		return rsa.decrypt(message, self._private)

	def publicKeyFingerprint(self):
		return publicKeyFingerprint(self._public_key)

	def decryptMessageB64(self, encrypted_message):
		return rsa.decrypt(base64.b64decode(encrypted_message), self._private_key).decode("utf-8")

class Session:
	def __init__(self, host, key):
		self._key = key
		self._host = host
		self._session_id = None

	def startSession(self, port):
		self._session_id = self._key.startSession(self._host, port)

	def stopSession(self):
		if self._session_id is None:
			return
		url, method = self._host.stopSessionURL()
		req_data = {
			"session_id": self._session_id,
		}
		response = requests.request(method, url, json=req_data)
		if not response.ok:
			raise Exception(response.text)

	def getSignatures(self):
		url, method = self._host.getSignaturesURL()
		req_data = {
			"key": self._key.publicKeyString()
		}
		response = requests.request(method, url, json=req_data)
		if not response.ok:
			raise Exception(response.text)
		return response.json()

class Permission:
	def __init__(self, permission_dir, name):
		self._file_path = os.path.join(permission_dir, name)
		self._config = None

		if not os.path.isdir(permission_dir):
			raise Exception("permission directory does not exist")

		if os.path.isfile(self._file_path):
			self._config = json.loads(open(self._file_path).read())
		else:
			self._config = {
				"authorized_keys": [],
			}
			self.updateConfigFile()

	def updateConfigFile(self):
		config_data = json.dumps(self._config)
		open(self._file_path, "w").write(config_data)

	def addAuthorizedKey(self, key_pem_string, name, organization):
		for ak in self._config["authorized_keys"]:
			if ak["key"] == key_pem_string:
				return # key already exists
		try:
			public_key_obj = pemStringToPublicKey(key_pem_string)
		except:
			return
		self._config["authorized_keys"].append({
			"key": key_pem_string,
			"name": name,
			"organization": organization,
		})
		self.updateConfigFile()

	def authorize(self, public_key_string, signature_base64, message, signer_public_key_string, filepath):
		for ak in self._config["authorized_keys"]:
			if ak["key"] == public_key_string:
				return True

		if not signature_base64 or not message or not signer_public_key_string:
			return False

		found = False
		for ak in self._config["authorized_keys"]:
			if ak["key"] == signer_public_key_string:
				found = True
				break
		if not found:
			return False

		now = int(time.time())
		if message["public_key"] != public_key_string:
			return False
		if message["start_time"] > now or message["end_time"] < now:
			return False

		message_string = signatureMessageToString(message)
		try:
			signer_public_key = pemStringToPublicKey(signer_public_key_string)
		except:
			return False
		try:
			signature = base64.b64decode(signature_base64)
		except:
			return False

		correct_modifier = True
		if message["modifiers"] != "":
			correct_modifier = False
			try:
				modifiers = parseModifiers(message["modifiers"])
				if modifiers is None:
					return False # could not modifiers
				if "cda" in modifiers and "encrypted_id" in modifiers["cda"]:
					encrypted_id = modifiers["cda"]["encrypted_id"]
					tree = ET.parse(filepath)
					patient_roles = tree.find("patientRole")
					for patientid in patient_roles.findall("id"):
						id_root = patientid.attrib["root"]
						if bcrypt.checkpw(id_root.encode("utf-8"), encrypted_id.encode("utf-8")):
							correct_modifier = True
							break
				else:
					return False # invalid modifier
			except Exception as e:
				raise e
				return False
		if not correct_modifier:
			return False

		return False if rsa.verify(message_string.encode("utf-8"), signature, signer_public_key) == False else True

	def getAuthorizedKeys(self):
		return self._config["authorized_keys"]
