from colorama import init, Fore
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


# Initializes Colorama
init(autoreset=True)

# create a log file 
LOG = os.path.join(os.getcwd(),'squatters.txt')
if not os.path.isfile(LOG):
    open(LOG,'w').write('')

fB = Fore.LIGHTBLUE_EX
fR = Fore.RED
fW = Fore.WHITE
fM = Fore.MAGENTA
fC = Fore.CYAN
fG = Fore.GREEN
fY = Fore.YELLOW
OFF = ''

top1m = pd.read_csv('top-1m.csv')
TOP_DOMAINS = list(top1m[:]['DOMAIN'])


def get_arecord_ip(host):
    ans = b''
    try:
        ans = str(dns.resolver.resolve(host, 'A')[0])
    except:
        pass
    return ans


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


def reverse_lookup(address):
    return str(dns.reversename.from_address(address))


def spot_a_squat(ts, domain, msg):
    for legit in TOP_DOMAINS:
        score = levenshtein(domain, legit)
        if 2 >= score > 0:
            print(f'{ts} {fR} {domain} {fW} {msg} [similar to {legit}?]')


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
            
            sus = False
            threads = multiprocessing.Pool(4)
            for real_domain in TOP_DOMAINS[0:900]:
                # test_domain(domain, real_domain, msg, tsfmt)
                event = threads.apply_async(test_domain, (domain,f'{real_domain}', msg, tsfmt))
                if event.get(3):
                    sus = True
                    break
            if not sus:
                IP = get_arecord_ip(domain.replace("*.",""))
                print(f'{tsfmt}{fG} {domain} {fW}was registered at {IP}')
            
        
def test_domain(dom_registered, dom_real, m, t):
    log_msg = u"[{}] {} (SAN: {})\n".format(t, dom_registered, m)
    score = levenshtein(dom_real, dom_registered)
    try:
        ip = get_arecord_ip(name)
    except:
        ip = ''
        pass
    if 2 > score >= 0:
        name = dom_registered.replace('*.','')
        log_msg = f'{t}{fB} {dom_registered} {fW}was registered {fW}[similar to {dom_real}? IP:{ip}]'
        print(log_msg)
        # Maybe also show the Location data?
        open(LOG,'a').write(u"[{}] {} (SAN: {} [similar to {dom_real}? IP:{ip})\n".format(t, dom_registered, m))
        return True
    else:
        return False

if __name__ == '__main__':
    if '--server' in sys.argv:
        os.system('python3 -m http.server &')
        # Use this to let other machines pull the squatter files on machine
        # useful if running seperate nodes for filtering different types of
        # domains or 'watcher.py' variants. 
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
    
