from translate import Translator
import multiprocessing
from parser import *
import requests
import random
import string
import json
import bs4
import sys
import os

BOLD = '\033[1m'
ITA = '\033[2m'
RED = '\033[31m'
GRN = '\033[32m'
YEL = '\033[33m'
BLU = '\033[34m'
END = '\033[0m'

translator= Translator(from_lang="ru",to_lang="en")

def extract_domains(parsedlog):
        domains = []
        for timestamp in parsedlog.keys():
                domain = parsedlog[timestamp]['domain']
                if domain not in domains:
                        domains.append(domain)
        print(f'\t[+] {len(domains)} unique domains found')
        return domains

def add_unique(domainset, domains):
        for address in domains:
                if address not in domainset:
                        domainset.append(address)
        return domainset

def pull_all_domains(path):
        logdata = {}
        unqiue_domains = []
        for f in os.listdir(path):
                # find sites
                print(f'[-] Parsing {f}')
                logdata[os.path.join(path,f)] = parse_log(os.path.join(path,f))
                unique_domains = add_unique(unqiue_domains, extract_domains(logdata[os.path.join(path,f)]))
        print(f'[+] {len(unqiue_domains)} found total')
        return logdata, unique_domains


def test_domain(address):
        # remove wildcard from domain registration if its there
        if address.find('*.') >=0 :
                address = address.split('*.')[1]
        # check what domain type ?
        tld = address.split('.')[-1]
        if tld == 'to':
                print(f'[!] Skipping address because it wont use http')
                return False, 'N/A'
        url = f'http://{address}'
        try:
                test = requests.get(url,timeout=5,verify=True)
                if test.status_code == 200:
                        print(f'{BOLD}{RED} {url} is live {END}')
                        #TODO: read page looking for malicious stuff or IOCs:
                        #       - javascript/external files like images
                        #       - tokens,cookies
                        #       - more embedded links
                        #       - connected subdomains (new ones)
                        return True, test.text

                else:
                        return False, test.status_code
        except:
                return False, 'CNX ERROR'


def find_links(html):
        links = []
        soup = bs4.BeautifulSoup(html, "lxml")
        for link in soup.findAll("a"):
                links.append(link)
        return links


def translate_tags(tag_type, html):
        results = []
       
        soup = bs4.BeautifulSoup(html)
        for element in soup.findAll(tag_type):
                if len(element.decode()) > 1:
                        item = element.decode().split('</')[0].split('>')[-1]
                        try:
                                # translalte to english?
                                translation = translator.translate(item)
                                print(f'{ITA}{BOLD}{YEL}\t<{tag_type}> {translation} {END} </{tag_type}>')
                                results.append(translation)
                        except:
                                results.append(item)
        return results

def crawl_domains(registrants, domains):
        livedomains = {}
        threads = multiprocessing.Pool(30)
        # start crawling 
        print(f'[-] Beginning Crawler...')
        for domain in domains:
                if os.path.isfile(f"results/{domain.replace('*','').replace('.','_')}.page"):
                        continue
                else:
                        # hasHtml, response = test_domain(domain)
                        event = threads.apply_async(test_domain, (domain,))
                        try:
                                hasHtml, response = event.get(7)
                        except multiprocessing.TimeoutError:
                                print(f'{BOLD}{YEL}[x] {END}')
                                continue
                        
                        if hasHtml:
                                TLD = domain.split('.')[-1]
                                fdump = f"results/{domain.replace('*','').replace('.','_')}.page"
                                if not os.path.isfile(fdump):
                                        open(fdump,'w').write(response)
                                        print(f'{YEL}{BOLD} - Wrote {len(response)} bytes to {fdump}{END}')
                                        urls = find_links(response)
                                        print(f'\t{BOLD}{len(urls)} Links found at {domain}')

                                else:
                                        continue

                        elif response != 'CNX ERROR':
                                color = ''
                                if response in [403, 302, 301]:
                                        color = GRN
                                print(f'[{response}]\t{domain}')
                                livedomains[domain] = response
        open('unviewable.json','w').write(json.dumps(livedomains))
        return livedomains



def main():
        if not os.path.isdir('results'):
                os.mkdir('results')
        r, d = pull_all_domains(os.path.join(os.getcwd(),'logs'))
        # shuffle the list to avoid hitting the same servers repeatedly if possible
        random.shuffle(domains)
        # Crawl through each domain
        liveones = crawl_domains(r, d)
        

if __name__ == '__main__':
        main()
