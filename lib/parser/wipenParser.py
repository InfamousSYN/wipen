#!/usr/bin/python3
from kamene.all import *
import re
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
        target_bssid_array = []
        if(self.target_bssid is not None):
            target_bssid_array.append(self.target_bssid)
        elif(self.target_bssid_list is not None):
            file_contents = open(self.target_bssid_list, 'r').readlines()
            for content in file_contents:
                target_bssid_array.append(content.rstrip('\n'))
        for tba in target_bssid_array:
            print('[+] The target bssid \'{}\' is similar to the following bssid and is broadcasting the following SSID'.format(tba))
            for pkt in self.packets:
                if(pkt.haslayer(Dot11Beacon)):
                    if(tba != pkt.addr3):
                        mangled_packet_address = pkt.addr3.split(':', self.depth)[:-1]
                        mangled_target_address = tba.split(':', self.depth)[:-1]
                        if(mangled_packet_address == mangled_target_address):
                            print('transmitter={} source={} ssid={} '.format(pkt.addr3, pkt.addr4, pkt.info.decode('utf-8')))
        return 0

    @classmethod
    def wipenParserIdentifyConnectedClients(self):
        target_bssid_array = []
        subType = [32]
        if(self.target_bssid is not None):
            target_bssid_array.append(self.target_bssid)
        elif(self.target_bssid_list is not None):
            file_contents = open(self.target_bssid_list, 'r').readlines()
            for content in file_contents:
                target_bssid_array.append(content.rstrip('\n'))
        for tba in target_bssid_array:
            print('[+] The target bssid \'{}\' the following connected clients were found:'.format(tba))
            for pkt in self.packets:
                if(pkt.haslayer(Dot11) and pkt.type == 2):
                    if(pkt.subtype == 0):
                        if(pkt.addr2 == tba):
                            print('bssid={} client={}'.format(pkt.addr2, pkt.addr1))
        return  0

    @classmethod
    def wipenParserMain(self, packets, target_ssid, target_ssid_list,
                        target_bssid, target_bssid_list, depth):
        self.packets = packets
        self.target_ssid = target_ssid
        self.target_ssid_list = target_ssid_list
        self.target_bssid = target_bssid
        self.target_bssid_list = target_bssid_list
        self.depth = depth

        if((self.target_ssid or self.target_ssid_list) is not None):
            self.wipenParserIdentifyBSSID()
        if((self.target_bssid or self.target_bssid_list) is not None):
            self.wipenParserIdentifySimilarBSSID()
            self.wipenParserIdentifyConnectedClients()
        return 0
