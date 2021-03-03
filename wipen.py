#!/usr/bin/python3
from kamene.all import *
from lib import settings
from lib import options as o

def printError(e):
    print('[!] Error:\r\n{}'.format(e))
    return 0

if __name__ == '__main__':
    try:
        option = o.wipenOptionClass.setOptions()
        if option == 1:
            raise
    except Exception as e:
        printError(e)
        exit(1)
    try:
        packets = rdpcap(option['pcap_filename'])
    except Exception as e:
        print('[!] Error reading pcap file: {}'.format(option['pcap_filename']))
exit(0)
