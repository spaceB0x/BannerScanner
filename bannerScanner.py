####### BannerScanner.py #######
# @version 1.0
# @date 3-1-14
# @author spaceB0x (tyler welton)
#
# Scans for headers on designated ports
# Hosts are verified using nmap, to reduce wasted time attempting
# connections on non existent clients.
#
# Spin-off of my other code -- WormScan
# Threading each scan!!! For maximum power level
# 
# "May we shout for joy over your victory and lift up our banners in the name 
#	of our God. May the Lord grant all your requests." Psalm 20:5

import os
import sys
import nmap
import socket
from socket import *
import optparse
from threading import *
screenLock= Semaphore(value=1)

def connScan(tgtHost, tgtPort, stringy):
	try:	
		
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send(stringy)
		results = connSkt.recv(400)
		screenLock.acquire()
		res=str(results)
		
		print '[+]%d/tcp open for %s %s' %(tgtPort, tgtHost, res)
		
		wfile.write('[+]%d/tcp open %s %s \n' %(tgtPort,tgtHost, res))
		#print'[+] '+ res
		wfile.write('[+] '+ res)
		connSkt.close()
	
	except:
		screenLock.acquire()
		print'[-]%d/ tcp closed for %s'% (tgtPort,tgtHost)
		wfile.write('[-]%d/ tcp closed for %s \n' %(tgtPort, tgtHost))
	finally:
		screenLock.release()
		connSkt.close()
		
def main():
	desc="""Attempts to grab banners from specified port, using custom "injection string"
		It takes the port number, ip range, output file, and string to be injected as parameters.
		When stating ip range; please don't use /24 format(eg. 10.x.x.0-255 instead of 10.x.x.0/24"""
		
	##Parse options
	parser=optparse.OptionParser("%prog "+ "-s <string> -i <ip_addresses> -p <port> -w <outputfile>", description=desc)
	parser.add_option('-s', dest='string', type='string',help='Input string to inject for service response')
	parser.add_option('-i', dest='hosts', type='string',help='IP address(es) formatted using "-" (not /24 format)')
	parser.add_option('-p', dest='port', type='int', help='Port to attemp injections on')
	parser.add_option('-w', dest='output', type='string', help='File to send results to')
	(options,args)=parser.parse_args()
	
	##Check for empty params
	if ((options.string==None) | (options.hosts==None)|(options.port==None)|(options.output==None)):
		os.system('bannerScanner.py --help')
		exit(0)
		
	##Define variables
	tgtPort=options.port
	tgtHost=options.hosts
	stringy=options.string
	global wfile 
	
	wfile = open('%s' %(options.output) ,'w')
	
	##scan (and populate a list using nmap)
	nm=nmap.PortScanner()
	nm.scan(hosts='%s' %tgtHost, arguments='-sn')
	hosts_list = [(str(nm[x]['addresses']['ipv4'])) for x in nm.all_hosts()]

	
	for x in hosts_list:
		t=Thread(target=connScan, args=(x,tgtPort,stringy))
		t.start()
	
	#wfile.close()

if __name__=='__main__':
	main()
	