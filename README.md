# nmap-nipper
sudo pip3 install -r requirements.txt
#
see all parameters or help: sudo python3 nmapripper.py -h
#
normal nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range]

e.g. sudo python3 nmapnipper.py -i 192.168.1.1 -p 1-8888
#
advanced nipper: sudo python3 nmapnipper.py -i [ipadress or ip range] -p [port or port range] -n [nmap options] -l [ip:port list] -r [save result list]

e.g. sudo python3 nmapnipper.py -i 192.168.1.1-255 -p 1-8888 -n "-sS -sV -T4" -l list.txt -r result.txt
#
scan nmap xml report: sudo python3 nmapripper.py -x [xmlfile]

e.g. sudo python3 nmapnipper.py -x nmapReport.xml
