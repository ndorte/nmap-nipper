**Nmap Nipper**

Nmap Ripper performs a standard Nmap scan. It then sends http, https, and socket requests to the open ports found. Records the responsed connection information and protocols.

*This program was made for pentests. The user is responsible for all illegal use. The program author is not responsible for illegal use.*

**Usage:**
 - Download and install Python modules `pip3 install -r requirements.txt`
 - See all parameters or help: `sudo python3 nmapripper.py -h`

 - Normal nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range]

e.g. `sudo python3 nmapnipper.py -i 192.168.1.1 -p 1-8888`
 
 - Advanced nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range] -n [nmap options] -l [ip:port list] -r [save result list]

e.g. `sudo python3 nmapnipper.py -i 192.168.1.1-255 -p 1-8888 -n "-sS -sV -T4" -l list.txt -r result.txt`
 
 - Scan nmap xml report: sudo python3 nmapripper.py -x [xmlfile]

e.g. `sudo python3 nmapnipper.py -x nmapReport.xml`
