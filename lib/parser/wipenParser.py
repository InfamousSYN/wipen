#!/usr/bin/python3
from kamene.all import *
import re
from lib import settings

class wipenParserClass():
    def __init__(self, packets):
        self.packets = None
        pass

    @staticmethod
    def getStandard(standard):
        # Derived from the 'channel flags' field of the RadioTap header layer
        standard_dict = {
            160:'802.11b', 320:'802.11a', 192:'802.11g',
            1152:'802.11n', 288:'802.11ac'
        }
        try:
            for key in standard_dict.keys():
                if(key == standard):
                    val = standard_dict[key]
            return val
        except Exception as e:
            return standard

    @staticmethod
    def getChannel(frequency):
        channel_dict = {
            2412:1, 2417:2, 2422:3, 2427:4, 2432:5,
            2442:6, 2447:7, 2452:9, 2457:10, 2462:11,
            2467:12, 2472:13, 2477:14,
            5180:36, 5200:40, 5220:44, 5240:48, 5260:52,
            5280:56, 5300:60, 5320:64, 5745:149, 5765:153,
            5785:157, 5805:161, 5825:165
        }
        try:
            for key in channel_dict.keys():
                if(key == frequency):
                    val = channel_dict[key]
            return val
        except Exception as e:
            return frequency

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
                        if(pkt.haslayer(RadioTap) == 0):
                            print('[!] The target cap file did not capture the RadioTap layer. In the future, capture 802.11 frames using Wireshark to include this information.')
                            print('ssid={} transmitter={} source={}'.format(pkt.info.decode('utf-8'), pkt.addr3, pkt.addr4))
                        else:
                            bytelist = (bytes(pkt.getlayer(RadioTap)))
                            channel_freq = int('0x{}{}'.format(hex(bytelist[19])[2:].zfill(2), hex(bytelist[18])[2:].zfill(2)), 16)
                            standard = int('0x{}{}'.format(hex(bytelist[21])[2:].zfill(2), hex(bytelist[20])[2:].zfill(2)), 16)
                            print('ssid={} transmitter={} source={} protocol={} freq={} channel={}'.format(pkt.info.decode('utf-8'), pkt.addr3, pkt.addr4, wipenParserClass.getStandard(standard), channel_freq, wipenParserClass.getChannel(channel_freq)))
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
    def wipenParserConnectedClientsProbes(self):
        target_client_array = []
        if(self.target_client is not None):
            target_client_array.append(self.target_client)
        elif(self.target_client_list is not None):
            file_contents = open(self.target_client_list, 'r').readlines()
            for content in file_contents:
                target_client_array.append(content.rstrip('\n'))
        for tca in target_client_array:
            print('[+] The target client \'{}\' is probing for the following SSID:'.format(tca))
            for pkt in self.packets:
                if(pkt.haslayer(Dot11ProbeReq)):
                    if(pkt.addr2 == tca):
                        print('client={} ssid={}'.format(pkt.addr2, pkt.info.decode('utf-8')))
        return 0

    @classmethod
    def wipenParserMain(self, packets, target_ssid, target_ssid_list,
                        target_bssid, target_bssid_list, depth,
                        target_client, target_client_list):
        self.packets = packets
        self.target_ssid = target_ssid
        self.target_ssid_list = target_ssid_list
        self.target_bssid = target_bssid
        self.target_bssid_list = target_bssid_list
        self.depth = depth
        self.target_client = target_client
        self.target_client_list = target_client_list

        if((self.target_ssid or self.target_ssid_list) is not None):
            self.wipenParserIdentifyBSSID()
        if((self.target_bssid or self.target_bssid_list) is not None):
            self.wipenParserIdentifySimilarBSSID()
            self.wipenParserIdentifyConnectedClients()
        if((self.target_client or self.target_client_list) is not None):
            self.wipenParserConnectedClientsProbes()
        return 0
