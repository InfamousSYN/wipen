#!/usr/bin/python3
from kamene.all import *
from lib import settings

class wipenParserClass():
    def __init__(self, packets):
        self.packets = None
        pass

    @classmethod
    def wipenParserIdentifyBSSID(self):
        target_ssid_array = []
        if(self.target_ssid is not None):
            target_ssid_array.append(self.target_ssid)
        elif(self.target_ssid_list is not None):
            file_contents = open(self.target_ssid_list, 'r').readlines()
            for content in file_contents:
                target_ssid_array.append(content.rstrip('\n'))
        for tsa in target_ssid_array:
            print('[+] The target ssid \'{}\' is broadcasted by the following infrastructure:'.format(tsa))
            for pkt in self.packets:
                if(pkt.haslayer(Dot11Beacon)):
                    if(tsa == pkt.info.decode('utf-8')):
                        print('ssid={} transmitter={} source={}'.format(pkt.info.decode('utf-8'), pkt.addr3, pkt.addr4))
        return 0

    @classmethod
    def wipenParserIdentifySimilarBSSID(self):
        return 0

    @classmethod
    def wipenParserMain(self, 
        packets, 
        target_ssid, 
        target_ssid_list):
        self.packets = packets
        self.target_ssid = target_ssid
        self.target_ssid_list = target_ssid_list

        self.wipenParserIdentifyBSSID()
        return 0
