# Linux Dumper (DD Forensic Imager over SSH)
# Author Mike Bangham (michael.bangham3@gmail.com)
# Inspired by the Forensic Focus Article by Chris Cohen https://www.forensicfocus.com/articles/asking-a-vps-to-image-itself/
# Python3 - tested on targets: Debian, Ubuntu, Lubuntu, Kubuntu, Raspbian, CentOS
# TO DO - option to push busybox to the target if dependencies are missing 

import os, sys
from os.path import join as pj
from getpass import getpass
import time
from tqdm import tqdm
import threading
import argparse
import pexpect
import ipaddress

SSH_NEWKEY = '(?i)are you sure you want to continue connecting'


def RepresentsInt(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False


def check_ip(ip):
	try:
		ip = ipaddress.ip_address(str(ip))
		return ip
	except ValueError:
		return False


def get_target_details():
	os.system('cls' if os.name == 'nt' else 'clear')
	operating_system = ''
	details_cmd = ('ssh {0}@{1} lsb_release -d'.format(args.TU, args.TI))

	child = pexpect.spawn('/bin/bash', ['-c', details_cmd]) # create a shell to pipe our dump command with
	i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[#$] ', '(?i)password'])
	if i == 0:
		print('[!] ERROR! SSH connection has failed.')
		sys.exit (1)
	if i == 1: # public key not cached.
		child.sendline ('yes')
		child.expect ('(?i)password')
	if i == 2:
		pass
	if i == 3:
		child.sendline(target_passwd)
		out = child.read().decode('ascii')
		child.terminate()

	if 'Description:' in out:
		for line in out.splitlines():
			if 'Description:' in line.strip():
				operating_system = line.lstrip().strip().rstrip().replace('Description:', '')
	return operating_system


def parse_partitions(shell_output):
	partitions = []
	shell_output = list(filter(None, shell_output.lstrip().strip().splitlines()))
	remove_list = ['/', '.', ' - ', '@', ':', '#']
	for r in remove_list:
		for i in shell_output:
			if r in i:
				try:
					shell_output.remove(i)
				except:
					pass
	for count, parts in enumerate(shell_output, start=0):
		col = parts.split(' ')
		col = [s for s in col if s != '']
		dev = col[3]
		size = col[2]
		size_mb = '{}MB'.format(str(round((int(col[2])*1024)/1000000)))
		partitions.append('{}. {} {} {}'.format(count,dev,size,size_mb))
	return partitions



def get_target_partitions():
	fdisk_cmd = ('ssh {0}@{1} cat /proc/partitions'.format(args.TU, args.TI))

	child = pexpect.spawn('/bin/bash', ['-c', fdisk_cmd]) # create a shell to pipe our dump command with
	i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[#$] ', '(?i)password'])
	if i == 0:
		print('[!] ERROR! SSH connection has failed.')
		sys.exit (1)
	if i == 1: # public key not cached.
		child.sendline ('yes')
		child.expect ('(?i)password')
	if i == 2:
		pass
	if i == 3:
		child.sendline(target_passwd)
		partitions = parse_partitions(child.read().decode('ascii'))
		child.terminate()

		print('')# print enter creates enough delay to gather the entire buff output
		for i in partitions:
			print(i)

		while True:
			chosen_partition = input('\n[*] Please type the index of the partition you would like to dump: ')
			if chosen_partition.isdigit():
				if int(chosen_partition) < len(partitions):
					break
			else:
				print('[!] Not an integer! Please select a number between 0 and {}'.format(len(partitions)-1))
		return (partitions[int(chosen_partition)]).split(' ')



def run(BLOCK_DEV, dump_filename):
	global running
	checksum = None

	dump_cmd = ('ssh {0}@{1} "sudo -S dd conv=sync,noerror bs={2}k if=/dev/{3} | tee >({4} >/dev/stderr) | gzip -{6} -" '
		'| dd bs={2} of={5}.gz'.format(args.TU, args.TI, args.BS, BLOCK_DEV, args.CS, dump_filename, args.Z))

	child = pexpect.spawn('/bin/bash', ['-c', dump_cmd]) # create a shell to pipe our dump command with
	i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[#$] ', '(?i)password'])
	if i == 0:
		print('[!] ERROR! could not login with SSH')
		sys.exit (1)
	if i == 1: # public key not cached.
		child.sendline ('yes')
		child.expect ('(?i)password')
	if i == 2:
		pass
	if i == 3:
		child.sendline(target_passwd)
		child.timeout = 36000
		out = child.read()
		child.terminate()
		shell_output = list(filter(None, out.lstrip().strip().splitlines()))[1:]
		for line in shell_output:
			if '-' in line.decode('ascii'):
				checksum = line.decode('ascii').replace('-','').strip()

		running = False
		time.sleep(0.5)
		if checksum:
			print('\n\n{}:\t{}'.format(args.CS, checksum))
			print('Finished Dumping!')
			checksum_tf = pj(os.getcwd(),'{}_checksum.md'.format(BLOCK_DEV))
			open(checksum_tf, 'a').close()
			with open(checksum_tf, 'w') as ctf:
				ctf.write(checksum)



def progress(total_size, partition, dump_filename):
	global running
	total_size = int(total_size)*1024
	print('Dumping {} from {}'.format(partition, args.TI))
	print('Block Size: {} | Compression Level: {} | Checksum: {}\n'.format(args.BS, args.Z, args.CS))
	pbar = tqdm(total=100, unit='B', unit_scale=True, desc='{}'.format(partition))
	for i in range(0,100):
		if running:
			while True:
				child = pexpect.spawn('stat {}.gz'.format(dump_filename))
				child.expect(dump_filename)
				buff = child.read().decode('ascii')
				child.terminate()

				shell_output = buff.lstrip().strip().strip('\t').strip('\n').rstrip()
				size = (shell_output[shell_output.index('Size: '):shell_output.index('Blocks: ')][6:]).strip()
				size = int(size)
				percent = round((size/total_size)*100)
				if not running:
					pbar.update(100-i)
					break
				if i == percent:
					pbar.update(1)
					break
				else:
					time.sleep(0.01)
				buff = ''
		else:
			sys.exit()


if __name__ == '__main__':
	print('\nLINUX SSH FORENSIC DUMPER')
	print("Append the '--help' command to see usage in detail")

	parser = argparse.ArgumentParser(description='Forensic Dump of a Linux OS over SSH')
	parser.add_argument('--TI', nargs='?', required=True, 
		help='The IP address of the target Linux machine.')
	parser.add_argument('--TU', nargs='?', required=True, 
		help='An admin account user of the target Linux machine. e.g. root')
	parser.add_argument('--Z', default='3', nargs='?', const='3', type=str, 
		help='gzip compression. 1 = min (fastest) | 9 = max (slowest). Default: 3')
	parser.add_argument('--BS', default='128', nargs='?', const='128', type=str, 
		help='Block size in KB, (e.g 64, 128, 1024, 65536). Default: 128')
	parser.add_argument('--CS', default='md5sum', nargs='?', const='md5sum', type=str, 
		help='Checksum the dump (cksum=CRC, md5sum=MD5, sha1sum=SHA1). Default: md5sum')

	args = parser.parse_args()

	global running
	running = True

	# check inputs
	if check_ip(args.TI):
		pass
	else:
		running = False
		print('[!] Error! The Target IP address entered is not valid.')
		sys.exit()
	if len(args.TU) < 2:
		print('[!] Error! The Target User is not valid.')
		running = False
		sys.exit()
	if RepresentsInt(args.BS) and (int(args.BS) <= 1310720) and (int(args.BS) % 16 == 0):
		pass
	else:
		running = False
		print('[!] Error! Block Size [--BS] must be less than or equal to 1310720 and be divisble by 16.')
		sys.exit()
	if RepresentsInt(args.Z) and int(args.Z) in range(1,10):
		pass
	else:
		running = False
		print('[!] Error! gzip compression [--Z] must be an integter between 1 and 9.')
		sys.exit()
	if args.CS in ['md5sum', 'cksum', 'sha1sum']:
		pass
	else:
		running = False
		print('[!] Error! Checksum [--CS] must be either "chsum", "md5sum" or "sha1sum".')
		sys.exit()

	# get target
	while True:
		print('\nPlease input the password for the target: {}'.format(args.TU))
		target_passwd = getpass()
		if len(target_passwd) > 0:
			break

	if running:
		target_details = get_target_details()
		print('LINUX SSH FORENSIC DUMPER')
		print('Partitions found on {}'.format(args.TI))
		if len(target_details) > 0:
			print('OS: {}'.format(target_details.lstrip()))
		BLOCK_DEV = get_target_partitions()
		dump_filename = '{}_{}_{}'.format(args.TU, args.TI, BLOCK_DEV[1])

		p1 = threading.Thread(target = run, args=(BLOCK_DEV[1], dump_filename))
		p1.start()
		p2 = threading.Thread(target = progress, args =(BLOCK_DEV[2], BLOCK_DEV[1], dump_filename))
		p2.start()
