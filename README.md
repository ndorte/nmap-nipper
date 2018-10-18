# nmap-nipper
pip3 install -r requirements.txt
#
usage: sudo python3 nmapnipper.py -i ipadress or iprange -p port or port range
#
e.g. sudo python3 nmapnipper.py -i 192.168.1.1 -p 1-1024
#
optional usage: sudo python3 nmapnipper.py -i 192.168.1.1 -p 1-1024 -n "-sS -sV -T4" -l target.txt -r result.txt
