import sys
from datetime import datetime
import urllib2
import json
from scapy.all import srp,Ether,ARP,conf

try:
    interface = raw_input("[*] Enter Interface: ")
    ips = raw_input("[*] Enter IP Range: ")

except KeyboardInterrupt:
    print "\n [!] Shutdown"
    sys.exit(1)

print "\n[+] Scanning ..."
start_time = datetime.now()


conf.verb = 0
ans, uans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout=2, iface=interface,inter=0.1)

macs = []

for snd, rcv in ans:
    mac = []
    mac.append(rcv.sprintf(r"%Ether.src%"))
    mac.append(rcv.sprintf(r"%ARP.psrc%"))
    macs.append(mac)
    #print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")




for mac in macs:
    api_mac = mac[0].replace(":","-")
    data = ""
    try:
        url = 'http://www.macvendorlookup.com/api/v2/'+api_mac
        response = urllib2.urlopen(url)
        try:
            data = json.load(response)
            company = data[0]['company']
        except:
            company = "no data"

    except Exception as e:
        print e
        print data
        exit(1)
        company = "No Data " + str(e)


    print company + "\n" + mac[1] + "\t(" + mac[0] + ")\n"

stop_time = datetime.now()
total_time = stop_time - start_time
print "\n[*] Scan Complete!"
print "\n[*] Scan Duration: %s" %(total_time)
