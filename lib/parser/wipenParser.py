#!/usr/bin/python3
from kamene.all import *
import re
import json
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
        # Derived from the 'channel frequency' field of the RadioTap header layer
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
            self.wipenJSONPayload.update({tsa: {"bssids":[]}} )
            for pkt in self.packets:
                if(pkt.haslayer(Dot11Beacon)):
                    if(tsa == pkt.info.decode('utf-8')):
                        if(pkt.haslayer(RadioTap) == 0):
                            self.wipenJSONPayload[tsa]['bssids'].append({
                                'bssid': pkt.addr3,
                                'source': pkt.addr4,
                                'protocol': None,
                                'channel': None,
                                'associated_clients': [],
                                'similar_bssids': []
                            })
                        else:
                            bytelist = (bytes(pkt.getlayer(RadioTap)))
                            channel_freq = int('0x{}{}'.format(hex(bytelist[19])[2:].zfill(2), hex(bytelist[18])[2:].zfill(2)), 16)
                            standard = int('0x{}{}'.format(hex(bytelist[21])[2:].zfill(2), hex(bytelist[20])[2:].zfill(2)), 16)

                            self.wipenJSONPayload[tsa]['bssids'].append({
                                'bssid': pkt.addr3,
                                'source': pkt.addr4,
                                'protocol': wipenParserClass.getStandard(standard),
                                'channel': wipenParserClass.getChannel(channel_freq),
                                'associated_clients': [],
                                'similar_bssids': []
                            })

            result = self.wipenJSONPayload

            ## removes duplicated entries from BSSIDS list
            new_list = []
            for line in result[tsa]['bssids']:
                if(line not in new_list):
                    new_list.append(line)
            self.wipenJSONPayload[tsa]['bssids'] = []
            self.wipenJSONPayload[tsa]['bssids'].append(new_list[0])
        return 0

    @classmethod
    def wipenParserIdentifySimilarBSSID(self):
        target_bssid_array = []

        for ssid in self.wipenJSONPayload:
            for bssid in self.wipenJSONPayload[ssid]['bssids']:
                target_bssid_array.append(bssid.get('bssid'))

            # iterate through target_bssid_array which is { (ssid): { 'bssids': [(bssid)]}}
            for tba in target_bssid_array:
                for pkt in self.packets:
                    if(pkt.haslayer(Dot11Beacon)):
                        # check to make that the bssid being search is not the same as found in pkt.addr3 field
                        if(tba != pkt.addr3):
                            mangled_packet_address = pkt.addr3.split(':', self.depth)[:-1]
                            mangled_target_address = tba.split(':', self.depth)[:-1]
                            # check to see if the first N fields of the MAC address based on the depth argument are the same
                            if(mangled_packet_address == mangled_target_address):
                                # add the found pkt.addr3 address to the `similar_bssids` filed of the json
                                # but we don't want to add the pkt.addr3 if it the same as the tba
                                # this will prevent wipen from flagging the bssid as a similar bssid as well
                                for bssid in self.wipenJSONPayload[ssid]['bssids']:
                                    if(bssid.get('bssid') == tba):
                                        bssid.get('similar_bssids').append({
                                                'bssid': pkt.addr3,
                                                'ssid': pkt.info.decode('utf-8')
                                            })
        return 0

    @classmethod
    def wipenParserIdentifyConnectedClients(self):
        target_bssid_array = []
        associated_clients_list = []
        Dot11subType = [0, 32, 36]
        bad_client_addr = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']
        for ssid in self.wipenJSONPayload:
            for bssid in self.wipenJSONPayload[ssid]['bssids']:
                target_bssid_array.append(bssid.get('bssid'))

            # iterate through target_bssid_array which is { (ssid): { 'bssids': [(bssid)]}}
            for pkt in self.packets:
                if((pkt.addr2 in target_bssid_array) and (pkt.subtype in Dot11subType)):
                    target_bssid_array_index = target_bssid_array.index(pkt.addr2)
                    # skip any bad addr from being added to associated client list
                    if(pkt.addr1 in bad_client_addr):
                        pass
                    else:
                        if(self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index].get('associated_clients') == []):
                            self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index].get('associated_clients').append({
                                'client_mac': pkt.addr1,
                                'probes': []
                                })
                            associated_clients_list.append(pkt.addr1)
                        else:
                            # ensure only 1 of each client address is added to the entry
                            for i in self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index].get('associated_clients')[0]:
                                if(self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index].get('associated_clients')[0].get('client_mac') not in associated_clients_list):
                                    associated_clients_list.append(self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index].get('associated_clients')[0].get('client_mac'))
                            # if already a known client, pass
                            if(pkt.addr1 in associated_clients_list):
                                pass
                            else:
                                self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index].get('associated_clients').append({
                                    'client_mac': pkt.addr1,
                                    'probes': []
                                    })
                                associated_clients_list.append(pkt.addr1)
        return  0

    @classmethod
    def wipenParserConnectedClientsProbes(self):
        target_bssid_array = []
        target_client_array = []

        for ssid in self.wipenJSONPayload:
            for bssid in self.wipenJSONPayload[ssid]['bssids']:
                target_bssid_array.append(bssid)
                for client in bssid.get('associated_clients'):
                    target_client_array.append(client.get('client_mac'))

                for pkt in self.packets:
                    if( (pkt.haslayer(Dot11ProbeReq) and pkt.addr2 in target_client_array) or (pkt.haslayer(Dot11Beacon) and pkt.addr3 in target_client_array)):
                        target_bssid_array_index = target_bssid_array.index(bssid)
                        if(pkt.haslayer(Dot11ProbeReq)):
                            target_client_array_index = target_client_array.index(pkt.addr2)
                        else:
                            target_client_array_index = target_client_array.index(pkt.addr3)
                        if(pkt.info.decode('utf-8') == ''):
                            pass
                        else:
                            if(pkt.info.decode('utf-8') in self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index]['associated_clients'][target_client_array_index].get('probes')):
                                pass
                            else:
                                self.wipenJSONPayload[ssid]['bssids'][target_bssid_array_index]['associated_clients'][target_client_array_index].get('probes').append(
                                    pkt.info.decode('utf-8')
                                    )
        return 0

    @classmethod
    def wipenParserMain(self, packets, target_ssid, target_ssid_list,
                        depth):
        self.packets = packets
        self.target_ssid = target_ssid
        self.target_ssid_list = target_ssid_list
        self.depth = depth
        self.wipenJSONPayload = {}

        if((self.target_ssid or self.target_ssid_list) is not None):
            self.wipenParserIdentifyBSSID()
            self.wipenParserIdentifySimilarBSSID()
            self.wipenParserIdentifyConnectedClients()
            self.wipenParserConnectedClientsProbes()
        return json.dumps(self.wipenJSONPayload)
