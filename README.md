# packet-sniffer
packet-sniffing application written in C using the pcap API.
# Installation  
Set execute permissions for the ``install.sh`` script (eg. ``sudo chmod 755 install.sh``) and  
run the script. This script will try to install the ``pcap`` library (if not installed) and build the sources.  
Run the program with root privileges: ``sudo ./sniffer [ -i ] interface [ -f ] filter expression``
