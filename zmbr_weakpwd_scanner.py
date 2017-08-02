#!/usr/bin/env python
__author__ = ('Imam Omar Mochtar', ('iomarmochtar@gmail.com',))

"""
License GPL V.2
Weak password scanner, built for zimbra.
Directly check to ldap data so admin DN bind is required.
You can see this repo https://github.com/danielmiessler/SecLists for weak password list that you can use
"""

import os
import sys
import re
import logging
import mmap
import ldap
import base64
from pprint import pprint
from hashlib import sha512, sha1
from tqdm import tqdm
from getpass import getpass
from time import sleep
from colorlog import ColoredFormatter
from argparse import ArgumentParser


class Scanner(object):

	base_dn = None
	url = None
	bind_dn = None
	bind_pwd = None
	ldap_filter = None
	result_file = None
	show_passwd = False
	passwdlst = None
	logger = logging.getLogger('PWDScanner')

	__l = None
	__result = []

	def __init__(self, bind_dn, result_file, passwdlst, ldap_filter=None, base_dn=None, show_passwd=False):
		self.bind_dn = bind_dn
		self.ldap_filter = ldap_filter
		self.base_dn = base_dn
		self.show_passwd = show_passwd
		self.result_file = result_file
		self.passwdlst = passwdlst

		formatter = ColoredFormatter(
			# "%(yellow)s%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(blue)s%(message)s",
			"%(yellow)s%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(log_color)s%(message)s",
			# datefmt=None,
			reset=True,
			log_colors={
				'DEBUG':	'cyan',
				'INFO':	 'green',
				'WARNING':  'yellow',
				'ERROR':	'red',
				'CRITICAL': 'red',
			}
		)

		handler = logging.StreamHandler()
		handler.setFormatter(formatter)

		self.logger.addHandler(handler)
		self.logger.setLevel(logging.DEBUG)



	def getLdapCon(self, dn, pwd):
		ldap.set_option(ldap.OPT_REFERRALS,0)
		ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,ldap.OPT_X_TLS_NEVER)

		l = ldap.initialize(self.url)
		try:
			l.simple_bind_s(dn, pwd)
		except ldap.INVALID_CREDENTIALS:
			self.logThenExit('Invalid ldap admin auth')

		return l


	def setBindPwd(self, passwd):
		if not passwd:
			return False
		self.bind_pwd = passwd


	def setUrl(self, url):
		"""
		LDAP url validator
		"""
		if not re.search('^ldap(s)?://', url):
			return False

		self.url = url
		return True

	def logThenExit(self, msg, stat='error', retcode=1):
		"""
		Logging kemudian exit
		"""
		log = getattr(self.logger, stat)

		log(msg)
		sys.exit(retcode)

	def lineCount(self, filename):
		f = open(filename, "r+")
		buf = mmap.mmap(f.fileno(), 0)
		lines = 0
		readline = buf.readline
		while readline():
			lines += 1
		return lines

	def readFile(self, rfile):
		with open(rfile) as lines:
			for line in lines:
				yield line.strip()

	def getCommontPasswd(self, username):
		commons = [username]
		return commons

	def getUserList(self, l):
		retattrs=['uid', 'userPassword', 'mail']
		lri = l.search(self.base_dn, ldap.SCOPE_SUBTREE, self.ldap_filter, retattrs)
		while True:
			result_type, result_data = l.result(lri, 0)
			if (result_data == []):
				break
			else:
				if result_type == ldap.RES_SEARCH_ENTRY:
					data = result_data[0]
					dn = data[0]
					attrs = dict( [(x,y[0]) for x,y in data[1].iteritems()] )
					pwd = attrs.get('userPassword')
					if not pwd:
						continue
					yield (dn, attrs)

	def getPasswordList(self, passwdlst):
		with open(passwdlst) as passwdfile:
			for passwd in passwdfile:
				yield passwd.strip()

	def dumpResult(self):
		if os.path.isfile(self.result_file):
			os.remove(self.result_file)

		if not self.__result:
			self.logger.warning("No user using weak password based on password list {0}".format(self.passwdlst))
			return

		with open(self.result_file, 'w') as tmp:
			for user, passwd in self.__result:
				tmp.write("{0}{1}\n".format(user,
					" :::: %s"%passwd if self.show_passwd else ""
				))
		self.logger.info("Password scanning result located at {0}".format(self.result_file))

	def getSaltPwd(self, hash_passwd):

		if hash_passwd.startswith('{SSHA512}'):
			striped = hash_passwd.replace('{SSHA512}', '')
			decoded = base64.b64decode(striped)
			return decoded[64::]

		elif hash_passwd.startswith('{SSHA}'):
			striped = hash_passwd.replace('{SSHA}', '')
			decoded = base64.b64decode(striped)
			return decoded[20::]

		return None

	# def encode(self, passwd, salt=os.urandom(16)):
	def encode(self, passwd, hash_passwd, salt=None):

		if not salt:
			if hash_passwd.startswith('{SHA}'):
				return "{{SHA}}{0}".format(
					base64.b64encode( sha1(passwd).digest() )
				)
		# If using salted hash
		else:
			mark = '{SSHA}'
			sha = sha1(passwd)
			if hash_passwd.startswith('{SSHA512}'):
				mark = '{SSHA512}'
				sha = sha512(passwd)

			sha.update(salt)
			return "{0}{1}".format(mark, base64.b64encode(sha.digest() + salt).decode('utf-8') )
		return None

	def verify(self, dn, passwd, hash_passwd, salt, pbar=None):

		hash_passwd_2 = self.encode(passwd, hash_passwd, salt)

		if hash_passwd == hash_passwd_2:
			# close progress bar if defined
			if pbar:
				pbar.close()

			self.logger.info("WEAK PASSWORD FOUND for user {0}{1}".format(dn,
				" ::: {0}".format( passwd ) if self.show_passwd else ""
			))
			self.__result.append((dn, passwd))
			return True
		return False


	def run(self):

		l = self.getLdapCon(self.bind_dn, self.bind_pwd)

		lcount = self.lineCount(self.passwdlst)
		users = [ x for x in self.getUserList(l) ]
		counter = 0
		for user in users:
			dn, attrs = user
			hash_passwd = attrs.get('userPassword')
			uid = attrs.get('uid')
			counter += 1

			self.logger.debug("{0} Password testing for dn:  {1}".format(
				"[%d/%d]"%(counter, len(users)), dn
			))

			# TODO: reuse password salt here
			salt = self.getSaltPwd(hash_passwd)

			cresult = False
			# TODO: chek common password
			for commonpasswd in self.getCommontPasswd(uid):
				cresult = self.verify(dn, commonpasswd, hash_passwd, salt)
				if cresult: break

			if cresult: continue

			with tqdm(total=lcount, ascii=True) as pbar:
				for passwd in self.getPasswordList(self.passwdlst):
					pbar.update(1)
					if self.verify(dn, passwd, hash_passwd, salt, pbar):
						break

		self.dumpResult()

if __name__ == '__main__':

	def isFileExist(parser, arg):
		if not os.path.exists(arg):
			parser.error("File %s doesn't exists"%arg)
		return arg

	parser = ArgumentParser(description='LDAP Weak Password Scanner, created by iomarmochtar@gmail.com')

	parser.add_argument('-p', '--password-file',
		help='Password file', type=lambda x: isFileExist(parser, x),
		action='store', required=True)

	parser.add_argument('-r', '--result-file',
		help='Dump result to file', action='store', default='/tmp/weak_user_passwd.txt')

	parser.add_argument('-l', '--ldap-url',
		help='LDAP url eg: ldap://ldap.someserver.com:389, use ldaps for ssl connection',
		action='store', required=True)

	parser.add_argument('-b', '--ldap-basedn',
		help='LDAP BaseDN, if not provide then all user will be scan', action='store', default='')

	parser.add_argument('-d', '--ldap-bind',
		help='LDAP Bind Admin', action='store', default='uid=zimbra,cn=admins,cn=zimbra')

	parser.add_argument('-s', '--show-password',
		help='Show weak password when it found', action='store_true', default=False)

	# exclude zimbra system and resource account
	parser.add_argument('-f', '--ldap-filter',
		help='LDAP Filter', action='store',
		default='(&(objectClass=zimbraAccount)(!(zimbraIsSystemAccount=TRUE))(!(zimbraIsSystemResource=TRUE)))')

	args = parser.parse_args()

	bf = Scanner(
		bind_dn=args.ldap_bind,
		result_file=args.result_file,
		passwdlst=args.password_file,
		ldap_filter=args.ldap_filter,
		base_dn=args.ldap_basedn,
		show_passwd=args.show_password
	)


	if bf.setBindPwd(getpass("Bind Password for {0}:".format(args.ldap_bind))):
		bf.logThenExit("You must input bind password")

	if not bf.setUrl(args.ldap_url):
		bf.logThenExit("Unknown url/server format")

	# check required path
	bf.run()

