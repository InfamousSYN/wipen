#!/usr/bin/python3
from scapy.all import *
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
        print('[+] Analysing file: {}'.format(option['pcap_filename']))
        packets = rdpcap(option['pcap_filename'])

        jsonPayload = wipenParser.wipenParserClass.wipenParserMain(
            packets=packets,
            target_ssid=option['target_ssid'],
            target_ssid_list=option['target_ssid_list'],
            depth=option['depth']
        )
        filename = '{}.json'.format(option['target_ssid'])
        print('[+] Result of analysis:\r\n{}'.format(jsonPayload))
        print('[+] Writing to file:\r\n{}'.format(filename))
        with open(filename, 'w') as file:
            file.write(jsonPayload)
        print('[+] {} packets analysed from file: {}'.format(len(packets), option['pcap_filename']))
    except Exception as e:
        print('[!] Error reading {}:\r\n{}'.format(option['pcap_filename'], e))
exit(0)
