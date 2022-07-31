import datetime
import random
import string
import json
import sys
import os

def random_filename(ext):
        alphas = list(string.ascii_lowercase)
        return f'{"".join(random.sample(alphas,6))}{ext}'

def exec_as_script(cmd):
        f = random_filename('.tmp')
        open(f,'w').write(f'#!/bin/bash\n{cmd}\nrm $0\n#EOF')
        return exec(f'bash {f}')

def exec(cmd):
        fout = random_filename('.txt')
        os.system(f'{cmd} > {fout}')
        result = open(fout,'r').read()
        os.remove(fout)
        return result.split('\n')

def list_all_logs(path):
        logs = {}

        if os.name == 'nt':
                cmd = f'dir {path}\\squatters*.txt'
                logs = find_lognames_nt(exec(cmd))

        return logs

def find_lognames_nt(filenames):
        files = []
        for fn in filenames:
                if fn.split(' ')[-1].find('.txt') > 0 and fn.split(' ')[-1].find('squat')==0:
                        print(f'[+] Found {fn.split(" ")[-1]}')
                        files.append(fn.split(' ')[-1])
        return files

def parse_log(fname):
        log = {}
        if not os.path.isfile(fname):
                print(f'[!] Unable to find {fname}')
                exit()
        raw_dns_data = open(fname,'r').read().split('\n')
        for ln in raw_dns_data:
                try:
                        fields = ln.split(' ')
                        date_day = fields[0].replace('[','')
                        date_time = fields[1].replace(']','')
                        dom_registered = fields[2]
                        registrant = fields[-1].replace('[','').replace(']','')
                        log[date_day+' '+date_time] = {'domain':dom_registered,
                                                                                                   'registrant': registrant}
                except IndexError:
                        pass
        # print(f'[-] {len(log.keys())} Entries Parsed')
        return log

def find_by_tld(data, tld):
        russian_ips = []
        russians = {}

        for timestamp in data.keys():
                entry = data[timestamp]
                if entry['domain'].split('.')[-1] == tld:
                        russian_ips.append(entry['registrant'])
        # Now make this a set 
        russian_ips = list(set(list(russian_ips)))
        for timestamp in data.keys():
                entry = data[timestamp]
                domain = entry['domain']
                ip = entry['registrant']
                if ip in russian_ips and ip not in russians.keys():
                        russians[ip] = []
                elif ip in russian_ips and ip in russians.keys():
                        russians[ip].append(domain)

        # return the organized data
        return russians

def combine_logs(parsed_logs):
        # method for combining logs without duplicating data
        megalog = {}
        master_list = []
        for log in parsed_logs:
                for ip in log.keys():
                        if ip not in megalog.keys():
                                megalog[ip] = []
                        master_list.append(ip)
        master_list = list(set(list(master_list)))
        len(master_list)

        for log in parsed_logs:
                for ip in log.keys():
                        for domain in log[ip]:
                                if domain not in megalog[ip]:
                                        megalog[ip].append(domain)
        return megalog


if __name__ == '__main__':
        logs = list_all_logs(os.getcwd())
        for logfile in logs:
                data = parse_log(logfile)
