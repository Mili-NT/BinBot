import os
from random import choice
import requests

user_agents = [
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'
]

def PrintSuccess(Msg):
	if os.name == 'nt':
		print('[+] ' + Msg)
	else:
		print('\033[1;32m[+]\033[1;m ' + Msg)

def PrintStatus(Msg):
	if os.name == 'nt':
		print('[*] ' + Msg)
	else:
		print('\033[1;34m[*]\033[1;m ' + Msg)

def PrintFailure(Msg):
	if os.name == 'nt':
		print('[-] ' + Msg)
	else:
		print('\033[1;31m[-]\033[1;m ' + Msg)

def PrintError(Msg):
	if os.name == 'nt':
		print('[!] ' + Msg)
	else:
		print('\033[1;31m[!]\033[1;m ' + Msg)

def PrintFatal(Msg):
	if os.name == 'nt':
		print('[$] ' + Msg)
	else:
		print('\033[1;33m[!]\033[1;m ' + Msg)

def DoNothing():
	pass

def random_headers():
	return { 'User-Agent': choice(user_agents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' }
