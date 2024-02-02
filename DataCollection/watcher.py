from colorama import init, Fore, Style
import multiprocessing
import pandas as pd
import dns.resolver
import numpy as np
import certstream
import datetime
import logging
import requests
import random
import json
import time
import sys
import os

# create a log file 
date_label = datetime.datetime.now().strftime('%m%d%y')
LOG = os.path.join(os.getcwd(),f'squatters{date_label}.txt')
if not os.path.isfile(LOG):
	open(LOG,'w').write('')

fB = Fore.LIGHTBLUE_EX
fR = Fore.RED
fW = Fore.WHITE
fO = Fore.YELLOW
fC = Fore.CYAN
fG = Fore.GREEN
fY = Fore.YELLOW
BOLD = Style.BRIGHT
OFF = '\033[0m'

top1m = pd.read_csv('top-1m.csv')
TOP_DOMAINS = list(top1m[:]['DOMAIN'])

def levenshtein(seq1, seq2):
	size_x = len(seq1) + 1
	size_y = len(seq2) + 1
	matrix = np.zeros ((size_x, size_y))
	for x in range(size_x):
		matrix [x, 0] = x
	for y in range(size_y):
		matrix [0, y] = y

	for x in range(1, size_x):
		for y in range(1, size_y):
			if seq1[x-1] == seq2[y-1]:
				matrix [x,y] = min(
					matrix[x-1, y] + 1,
					matrix[x-1, y-1],
					matrix[x, y-1] + 1
				)
			else:
				matrix [x,y] = min(
					matrix[x-1,y] + 1,
					matrix[x-1,y-1] + 1,
					matrix[x,y-1] + 1
				)
	return matrix[size_x - 1, size_y - 1]

def get_arecord_ip(host):
	ans = b''
	try:
		ans = str(dns.resolver.resolve(host, 'A')[0])
	except:
		pass
	return ans

def test_domain(dom_registered, dom_real, t):
	score = levenshtein(dom_real, dom_registered)
	try:
		ip = get_arecord_ip(name)
	except:
		ip = ''
		pass
	if 3 > score >= 0:
		name = dom_registered.replace('*.','')
		log_msg = f'{t} {dom_registered} was registered [similar to {dom_real}? IP:{ip}]'
		print(log_msg)
		open(LOG,'a').write(f"[{t}] {dom_registered} [similar to {dom_real}? IP:{ip})\n")
		# Maybe also show the Location data?
		return True
	else:
		return False

def print_callback(message, context):
	logging.debug("Message -> {}".format(message))
	if message['message_type'] == "heartbeat":
		return

	if message['message_type'] == "certificate_update":
		all_domains = message['data']['leaf_cert']['all_domains']

		if len(all_domains) == 0:
			domain = "NULL"
		else:
			domain = all_domains[0]
			tsfmt = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')
			msg = " , ".join(message['data']['leaf_cert']['all_domains'][1:])
			try:
				IP =get_arecord_ip(domain.replace("*.", ""))
			except:
				IP = ''
				pass
			
			sus = False
			C = ''
			msg = f"[{tsfmt}] {domain} registered to {IP}\n"
			if domain.split('.')[-1] in ['ru','cn','hk', 'kp','ir']:
				open(LOG,'a').write(msg)
				C = BOLD + fC
			elif domain.split('.')[-1] in ['xyz','party', 'download','gg', 'stream','cloud','help','cc']:
				open(LOG,'a').write(msg)
				C = BOLD + fY
			
			print(f'{tsfmt} {C}{domain}{OFF} was registered at {fR}{IP}{OFF}')

if __name__ == '__main__':
	if '--server' in sys.argv:
		os.system('python3 -m http.server &')
		# Use this to let other machines pull the squatter files on machine
		# useful if running seperate nodes for filtering different types of
		# domains or 'watcher.py' variants. 
	logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
	certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
	