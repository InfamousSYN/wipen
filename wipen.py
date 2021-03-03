#!/usr/bin/python3
from kamene.all import *
from lib import settings
from lib import options as o
from lib.parser import wipenParser

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
        wipenParser.wipenParserClass.wipenParserMain(
            packets=packets,
            target_ssid=option['target_ssid'],
            target_ssid_list=option['target_ssid_list'],
            target_bssid=option['target_bssid'],
            target_bssid_list=option['target_bssid_list'],
            depth=option['depth'],
            target_client=option['target_client'],
            target_client_list=option['target_client_list']
        )
    except Exception as e:
        print('[!] Error reading {}:\r\n{}'.format(option['pcap_filename'], e))
exit(0)
