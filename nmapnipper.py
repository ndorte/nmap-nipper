#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import nmap
import socket
import time
import requests
import bs4
import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

print('''
 _   _                         _   _ _                       
| \ | |                       | \ | (_)                      
|  \| |_ __ ___   __ _ _ __   |  \| |_ _ __  _ __   ___ _ __ 
| . ` | '_ ` _ \ / _` | '_ \  | . ` | | '_ \| '_ \ / _ \ '__|
| |\  | | | | | | (_| | |_) | | |\  | | |_) | |_) |  __/ |   
|_| \_|_| |_| |_|\__,_| .__/  |_| \_|_| .__/| .__/ \___|_|   
                      | |             | |   | |              
                      |_|             |_|   |_|              

by Uğur Kubilay Çam
https://github.com/ndorte/nmap-nipper
''')

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="ip address or ip range. e.g. 192.168.1.1, 192.168.1.0/24")
parser.add_argument("-p", "--port", help="port or port range. e.g. 80, 1-1024")
parser.add_argument("-n", "--nmap", help="nmap args. default: -sS -T4", nargs='?', type=str, default="-sS -T 4")
parser.add_argument("-l", "--list", help="scan list. default: list.txt", nargs='?', type=str, default="list.txt")
parser.add_argument("-r", "--result", help="result list. default: result.txt", nargs='?', type=str,
                    default="result.txt")
parser.add_argument("-x", "--xml", help="you can scan nmap xml report", nargs='?', type=str, default="none")
args = parser.parse_args()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

try:
    with open(args.result, "w") as results:
        results.writelines("Host" + (" " * 17) + "\tConnection" + (" " * 3) + "\tCode" + (" " * 6) + "\tTitle / Message\n" +
                           ("-" * 20) + "\t" + ("-" * 13) + "\t" + ("-" * 10) + "\t" + ("-" * 27))
        results.close()


    def nmap_scan(ip, port, nmapargs):
        nm = nmap.PortScanner()
        nm.scan(ip, port, arguments=nmapargs)
        scanlist = list()
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(bcolors.OKGREEN + '[+] Host : %s (%s)' % (host, nm[host].hostname()))
            else:
                continue
            for protokol in nm[host].all_protocols():
                lport = nm[host][protokol].keys()
                for port in lport:
                    add = (host + ":" + str(port) + "\n")
                    scanlist.append(add)
                    print(bcolors.OKGREEN + '[+] %s %s:%s is open. Added to target list' % (protokol, host, port))
        with open(args.list, "w") as lists:
            lists.writelines(scanlist)
            lists.close()
            print(bcolors.OKBLUE + "[!] Target list saved.")
            time.sleep(2)


    def socketResponse(host):
        portParse = list(map(str, host.split(":")))
        ip = portParse[0]
        port = int(portParse[1])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.settimeout(2)
        mesaj = (s.recv(4096))
        kaydet = str(mesaj)
        resultadd(host, "Socket", "-", kaydet)
        print(bcolors.OKGREEN + "[+] " + host + " Socket responded and was added to the result list. Msg: " + str(mesaj))


    def httpResponse(host):
        http = ("http://" + host)
        s = requests.get(http, verify=False, timeout=2)
        soup = bs4.BeautifulSoup(s.text, "html.parser")
        a = soup.find("title")
        if a is None:
            title = "None"
        else:
            title = a.string
        resultadd(host, "Http", str(s.status_code), title)
        print(
            bcolors.OKGREEN + "[+] " + host + " Http responded and was added to the result list. Title: " + title + ", Code: " + str(
                s.status_code))


    def httpsResponse(host):
        https = ("https://" + host)
        s = requests.get(https, verify=False, timeout=2)
        soup = bs4.BeautifulSoup(s.text, "html.parser")
        a = soup.find("title")
        if a is None:
            title = "None"
        else:
            title = a.string
        resultadd(host, "Https", str(s.status_code), title)
        print(
            bcolors.OKGREEN + "[+] " + host + " Https responded and was added to the result list. Title: " + title + ", Code: " + str(
                s.status_code))


    def port_scan():
        with open(args.list, "r") as list:
            for i in list.readlines():
                host = i.strip()
                try:
                    httpResponse(host)
                except:
                    print(bcolors.FAIL + "[-] " + host + " Http did not respond")
                try:
                    httpsResponse(host)
                except:
                    print(bcolors.FAIL + "[-] " + host + " Https did not respond")
                try:
                    socketResponse(host)
                except:
                    print(bcolors.FAIL + "[-] " + host + " Socket did not respond")


    def resultadd(host, connection, code, title):
        with open(args.result, "a") as results:
            results.writelines("\n" + host + (" " * (21 - len(host))) + "\t" + connection + (
                    " " * (13 - len(connection))) + "\t" + code + (" " * (10 - len(code))) + "\t" + title)
            results.close()


    def xml_parser(file):
        print(bcolors.OKBLUE + "[!] Parsing Nmap xml file..")
        parse_list = list()
        for host in file.hosts:
            ip = host.address
            if host.is_up():
                for s in host.services:
                    if s.open():
                        port = s.port
                        ipport = (str(ip) + ":" + str(port) + "\n")
                        parse_list.append(ipport)
        with open("list.txt", "w") as xml:
            xml.writelines(parse_list)
            xml.close()
            print(bcolors.OKBLUE + "[!] Nmap xml file parsed > list.txt")


    def xmlnipper():
        file = NmapParser.parse_fromfile(args.xml)
        xml_parser(file)

    if args.xml == "none":
        print(bcolors.OKBLUE + "[!] Nmap scan started. It may take a few minutes")
        nmap_scan(args.ip, args.port, args.nmap)
        print(bcolors.OKBLUE + "[!] Starting Http, Https, Socket scan..")
        port_scan()
    else:
        xmlnipper()
        print(bcolors.OKBLUE + "[!] Starting Http, Https, Socket scan..")
        port_scan()
except:
    print('''
Error!

see all parameters or help: sudo python3 nmapripper.py -h

normal nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range]
e.g. sudo python3 nmapnipper.py -i 192.168.1.1 -p 1-8888

advanced nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range] -n [nmap options] -l [ip:port list] -r [save result list]
e.g. sudo python3 nmapnipper.py -i 192.168.1.1-255 -p 1-8888 -n "-sS -sV -T4" -l list.txt -r result.txt

nmap xml report nipper: sudo python3 nmapripper.py -x [xmlfile]
e.g. sudo python3 nmapnipper.py -x nmapReport.xml
    
    ''')
