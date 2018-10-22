#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import nmap, socket, time, requests, bs4, argparse
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
Python 4 Hackers > https://www.python4hackers.com

''')

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="ip address or ip range. e.g. 192.168.1.1, 192.168.1.0/24")
parser.add_argument("-p", "--port", help="port or port range. e.g. 80, 1-1024")
parser.add_argument("-n", "--nmap", help="nmap args. default: -sS -T4", nargs='?', type=str, default="-sS -T4")
parser.add_argument("-l", "--list", help="scan list. default: list.txt", nargs='?', type=str, default="list.txt")
parser.add_argument("-r", "--result", help="result list. default: result.txt", nargs='?', type=str,
                    default="result.txt")
parser.add_argument("-x", "--xml", help="you can scan nmap xml report", nargs='?', type=str, default="none")
args = parser.parse_args()


class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'


try:
    with open(args.result, "w") as results:
        results.writelines(
            "Host{}\tConnection{}\tCode{}\tTitle / Message\n{}\t{}\t{}\t{}".format((" " * 19), (" " * 3), (" " * 6),
                                                                                   ("-" * 23), ("-" * 13), ("-" * 10),
                                                                                   ("-" * 27)))
        results.close()


    def nmap_scan(ip, port, nmapargs):
        nm = nmap.PortScanner()
        nm.scan(ip, port, arguments=nmapargs)
        scanlist = list()
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(bcolors.OKGREEN + '[+] Host : {} ({})'.format(host, nm[host].hostname()))
            else:
                continue
            for protokol in nm[host].all_protocols():
                lport = nm[host][protokol].keys()
                for port in lport:
                    add = (host + ":" + str(port) + "\n")
                    scanlist.append(add)
                    print(bcolors.OKGREEN + '[+] {} {}:{} is open. Added to target list'.format(protokol, host, port))
        with open(args.list, "w") as lists:
            lists.writelines(scanlist)
            lists.close()
            print(bcolors.OKBLUE + "[!] Target list saved.")
            time.sleep(2)


    def socket_response(host):
        portParse = list(map(str, host.split(":")))
        ip = portParse[0]
        port = int(portParse[1])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.settimeout(2)
        mesaj = (s.recv(4096))
        kaydet = str(mesaj)
        result_add(host, "Socket", "-", kaydet)
        print(
            bcolors.OKGREEN + "[+] {} Socket responded and was added to the result list. Msg: {}".format(host,
                                                                                                         str(mesaj)))


    def http_response(host):
        http = ("http://" + host)
        s = requests.get(http, verify=False, timeout=2)
        soup = bs4.BeautifulSoup(s.text, "html.parser")
        a = soup.find("title")
        if a is None:
            title = "None"
        else:
            title = a.string
        result_add(host, "Http", str(s.status_code), title)
        print(
            bcolors.OKGREEN + "[+] {} Http responded and was added to the result list. Title: {}, Code: {}".format(host,
                                                                                                                   title,
                                                                                                                   str(
                                                                                                                       s.status_code)))


    def https_response(host):
        https = ("https://" + host)
        s = requests.get(https, verify=False, timeout=2)
        soup = bs4.BeautifulSoup(s.text, "html.parser")
        a = soup.find("title")
        if a is None:
            title = "None"
        else:
            title = a.string
        result_add(host, "Https", str(s.status_code), title)
        print(bcolors.OKGREEN + "[+] {} Https responded and was added to the result list. Title: {}, Code: {}".format(
            host, title, str(s.status_code)))


    def port_scan():
        with open(args.list, "r") as rdlist:
            for i in rdlist.readlines():
                host = i.strip()
                try:
                    http_response(host)
                except:
                    print(bcolors.FAIL + "[-] {} Http did not respond".format(host))
                try:
                    https_response(host)
                except:
                    print(bcolors.FAIL + "[-] {} Https did not respond".format(host))
                try:
                    socket_response(host)
                except:
                    print(bcolors.FAIL + "[-] {} Socket did not respond".format(host))


    def result_add(host, connection, code, title):
        with open(args.result, "a") as results:
            results.writelines("\n{}{}\t{}{}\t{}{}\t{}".format(host, (" " * (23 - len(host))), connection,
                                                               (" " * (13 - len(connection))), code,
                                                               (" " * (10 - len(code))), title))
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


    def xml_nipper():
        file = NmapParser.parse_fromfile(args.xml)
        xml_parser(file)


    def scan_with_nmap():
        print(bcolors.OKBLUE + "[!] Nmap scan started. It may take a few minutes")
        nmap_scan(args.ip, args.port, args.nmap)
        print(bcolors.OKBLUE + "[!] Starting Http, Https, Socket scan..")
        port_scan()


    def scan_with_xml():
        xml_nipper()
        print(bcolors.OKBLUE + "[!] Starting Http, Https, Socket scan..")
        port_scan()


    if args.xml == "none":
        scan_with_nmap()
    else:
        scan_with_xml()

except:
    print('''
Error!

see all parameters or help: sudo python3 nmapnipper.py -h
normal nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range]
e.g. sudo python3 nmapnipper.py -i 192.168.1.1 -p 1-8888

advanced nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range] -n [nmap options] -l [ip:port list] -r [save result list]
e.g. sudo python3 nmapnipper.py -i 192.168.1.1-255 -p 1-8888 -n "-sS -sV -T4" -l list.txt -r result.txt

nmap xml report nipper: sudo python3 nmapripper.py -x [xmlfile]
e.g. sudo python3 nmapnipper.py -x nmapReport.xml
''')
