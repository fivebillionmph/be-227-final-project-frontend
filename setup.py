from setuptools import setup

setup(
	name = "securep2p227",
	version = "0.1",
	packages = ["securep2p227"],
	install_requires = [
		"rsa",
		"requests",
		"cryptography"
	],
)
