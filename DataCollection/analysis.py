import multiprocessing
from crawler import *
from parser import *
import random
import string
import dotenv
import random
from colorama import init, Fore

fB = Fore.LIGHTBLUE_EX
fR = Fore.RED
fW = Fore.WHITE
fM = Fore.MAGENTA
fC = Fore.CYAN
fG = Fore.GREEN
fY = Fore.YELLOW
fO = '\033[1m' # Bold on 
fE = '\033[0m' # Bold end

def load_nodes():
	if os.path.isfile('.env'):
		dotenv.load_dotenv()
		# find nodes 
		nodes = {}
		for item in os.environ.keys():
			if item.find('NODE') >=0:
				nodes[item] = os.environ[item]
	else:
		print('[!] Missing .env file')
		exit()
	return nodes 

def list_data(label, node):
	if not os.path.isdir(label.upper()):
		os.mkdir(label.upper())
	uname = node.split('@')[0]
	cmd = f'ssh {node} ls /home/{uname}/Titleist/DataCollection/squatters*'
	for filename in exec(cmd):
		if len(filename) > 1:
			if not os.path.isfile(os.path.join(os.getcwd(),label,filename.split('/')[-1])):
				print(f'{fO}- found {fR}{filename}{fE}{fO} on {fY}{node}{fE}')
				get_file = f"cd {label}; sftp {node}:/home/{uname}/Titleist/DataCollection/ <<< $'get {filename}';cd .."
				exec_as_script(get_file)
			else:
				print(f'{fO}- already have {fG}{filename}{fE}{fO} from {fC}{node}{fE}')
				log_data = parse_log(os.path.join(os.getcwd(),label,filename.split('/')[-1]))
				print(f'\t-{len(log_data.keys())} entries parsed')

def main():
	collectors = load_nodes()
	for label, node in collectors.items():
		print('='*88)
		print(f'[+] Checking in with{fE} {fY}{label}{fE}')
		list_data(label, node)
		r, d = pull_all_domains(os.path.join(os.getcwd(),label))
		random.shuffle(d)
		liveones = crawl_domains(r, d)


if __name__ == '__main__':
	main()