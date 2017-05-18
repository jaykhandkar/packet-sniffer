if [ $(whereis pcap | wc -m) -lt 7 ]				#pcap not installed
then
	echo "pcap not found, will try and install"
	if [ $(whereis apt-get | wc -m) -lt 9 ];then  #check which packet manager
		sudo yum install libpcap-devel
		if [ $? != 0 ];then		      #installation failed
			echo "couldn't install required libraries"
			echo "stop"
			exit
		fi
	else
		sudo apt-get install libpcap-dev
		if [ $? != 0 ];then
			echo "couldn't install required libraries"
			echo "stop"
			exit
		fi
	fi
fi
echo "libraries installed, buiding..."				#pcap found/installed
make sniffer
