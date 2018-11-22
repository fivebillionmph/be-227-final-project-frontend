import os
import rsa
import json
import requests
import base64

_PRIVATE_KEY_FILE_NAME = "private-key"
_PUBLIC_KEY_FILE_NAME = "public-key"
_INFO_FILE_NAME = "info"

def getKey(key_dir, name):
	if not os.isdir(os.path.join(key_dir, name)):
		raise Exception("key directory does not exist")

	private_key_file = os.path.join(key_dir, name, _PRIVATE_KEY_FILE_NAME)
	public_key_file = os.path.join(key_dir, name, _PUBLIC_KEY_FILE_NAME)
	info_file = os.path.join(key_dir, name, _INFO_FILE_NAME)

	if not os.isfile(private_key_file) or not os.isfile(public_key_file) or not os.isfile(info_file):
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

class Host:
	protocol = "http"

	def __init__(self, fqdn):
		self._fqdn = fqdn

	def registerURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/register", "PUT")

	def registerChallengeURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/register/challenge", "PUT")

	def startSessionURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/session", "POST")

	def startSessionChallengeURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/session/challenge", "PUT")

	def getSessionsURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/sessions", "GET")

	def getSignaturesURL(self):
		return (self.protocol + "://" + self._fqdn + "/a/signatures", "GET")

class Key:
	def __init__(self, private_key, public_key, dir_path, name, organization):
		self._private_key = private_key
		self._public_key = public_key
		self._dir_path = dir_path
		self._name = name
		self._organization = organization

	def publicKeyString(self):
		return self._public_key.save_pkcs1().decode("utf-8")

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

class Session:
	def __init__(self, host, key):
		self._key = key
		self._host = host
		self._session_id = None

	def startSession(self, port):
		self._session_id = self._key.startSession(self._host, port)

	def getActiveSessions(self):
		url, method = self._host.getSessionsURL()
		response = requests.request(method, url)
		if not response.ok:
			raise Exception(response.text)
		return response.json()

	def getSignatures(self):
		url, method = self._host.getSignaturesURL()
		response = requests.request(method, url + "?key=" + self._key.publicKeyString())
		if not response.ok:
			raise Exception(response.text)
		return response.json()
