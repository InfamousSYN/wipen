#!/usr/bin/python3
from scapy.all import *
import re
import sys
import uuid
from datetime import datetime
from lib import settings
import mac_vendor_lookup

class wipenParserClass():
    @classmethod
    def __init__(self, verbose, depth, ssid_pattern, filename, ignore_bssid, ignore_client, disable_vendor_mac_refresh, periodic_file_update, skip_similar, **kwargs):
        import threading
        self.wipenJSONPayload = {}
        self.verbose = verbose
        self.target_ssid = None
        self.depth = depth
        self.ssid_pattern=ssid_pattern,
        self.filename = filename
        self.ignore_bssid = ignore_bssid
        self.ignore_client = ignore_client
        self.disable_vendor_mac_refresh = disable_vendor_mac_refresh
        self.periodic_file_update = periodic_file_update*60
        self.skip_similar = skip_similar

        # Reset from tuple to list
        if(self.ssid_pattern[0] is not None):
            _ssid_pattern_reset = self.ssid_pattern
            self.ssid_pattern = list()
            for ssids in _ssid_pattern_reset:
                for ssid in ssids:
                    self.ssid_pattern.append(ssid)

        self.mac = mac_vendor_lookup.MacLookup()
        if(not self.disable_vendor_mac_refresh):
            print('[-] Refreshing vendor MAC table list')
            self.mac.update_vendors()

        threading.Thread(target=self.periodicJSONPayloadFileWrite, daemon=True).start()

    @staticmethod
    def get_object_type(obj=None):
        try:
            if(obj.lower()=='ssid'):
                return 'ssid'
            if(obj.lower()=='bssid'):
                return 'bssid'
            if(obj.lower()=='sta'):
                return 'sta'
            if(obj.lower()=='identity'):
                return 'identity'
            if(obj.lower()=='probe'):
                return 'probe'
        except Exception as e:
            raise

    @classmethod
    def get_new_uuid(self):
        result = uuid.uuid4()
        if(result not in self.deep_search(
            target_key='id',
            payload=self.wipenJSONPayload)):
            return '{}'.format(result)
        else:
            self.get_new_uuid()


    @staticmethod
    def getStandard(standard=None, packet=None):
        # Derived from the 'channel flags' field of the RadioTap header layer
        standard_dict = {
            160:'802.11b', 320:'802.11a', 192:'802.11g',
            1152:'802.11n', 288:'802.11ac', None:'802.11ax', None:'802.11be'
        }
        try:
            for key in standard_dict.keys():
                if(key == standard):
                    val = standard_dict.get(key)
            dot11elt = packet.getlayer(Dot11Elt)
            _HT_STATUS = False
            _VHT_STATUS = False

            while dot11elt:
                if( (dot11elt.name == '802.11 HT Capabilities' and dot11elt.ID == 0x2d) ):
                    _HT_STATUS = True
                if( (dot11elt.name == '802.11 Information Element' and dot11elt.ID == 0xbf) ):
                    _VHT_STATUS = True
                dot11elt = dot11elt.payload.getlayer(Dot11Elt)

            if( (val == '802.11a' or val == '802.11a') and _VHT_STATUS):
                val = '802.11ac'
            return val
        except Exception as e:
            return '{}'.format(standard)

    @staticmethod
    def getChannel(frequency):
        # Derived from the 'channel frequency' field of the RadioTap header layer
        channel_dict = {
            2412:1, 2417:2, 2422:3, 2427:4, 2432:5, 2437:6, 2442:7, 2447:8, 2452:9,
            2457:10, 2462:11, 2467:12, 2472:13, 2484:14,
            5160:32, 5170:34, 5180:36, 5190:38,
            5200:40, 5210:42, 5220:44, 5230:46, 5240:48,
            5250:50, 5260:52, 5270:54, 5280:56, 5290:58,
            5300:60, 5310:62, 5320:64, 5340:68,
            5480:96,
            5500:100, 5510:102, 5520:104, 5530:106, 5540:108,
            5550:110, 5560:112, 5570:114, 5580:116, 5590:118,
            5600:120, 5610:122, 5620:124, 5630:126, 5640:128,
            5660:132, 5670:134, 5680:136, 5690:138,
            5700:140, 5710:142, 5720:142, 5745:149,
            5755:151, 5765:153, 5775:155, 5785:157, 5795:159,
            5805:161, 5815:163, 5825:165, 5835:167, 5845:169,
            5855:171, 5865:173, 5875:175, 5885:177,
            4915:183, 4920:184, 4925:185, 4935:187, 4940:188, 4945:189,
            4960:192, 4980:196
        }
        try:
            for key in channel_dict.keys():
                if(key == frequency):
                    val = channel_dict[key]
            return val
        except Exception as e:
            return frequency

    @staticmethod
    def getAuthentication(packet):
        if(packet.haslayer(Dot11Beacon)):
            auth = ''.join(packet.getlayer(Dot11Beacon).network_stats().get('crypto'))
        elif(packet.haslayer(Dot11ProbeResp)):
            auth = ''.join(packet.getlayer(Dot11ProbeResp).network_stats().get('crypto'))
        else:
            auth = None
        return auth

    @staticmethod
    def check_SIMILAR_BSSID_HIDDEN_STATUS(ssid=None, parent_bssid=None, similar_bssid=None, payload=None):
        hidden_ssid = None
        for _known_bssid_pos, _known_bssid in enumerate(payload[ssid]['bssid']):
            if(parent_bssid == _known_bssid.get('bssid')):
                for _known_bssid_similiar_bssid_pos, _known_bssid_similiar_bssid in enumerate(payload[ssid]['bssid'][_known_bssid_pos]['similar_bssid']):
                    if(similar_bssid == _known_bssid_similiar_bssid.get('bssid')):
                        hidden_ssid = payload[ssid]['bssid'][_known_bssid_pos]['similar_bssid'][_known_bssid_similiar_bssid_pos].get('hidden_ssid')
        if(hidden_ssid):
            return True
        else:
            return False

    @staticmethod
    def deep_search(target_key=None, payload=None):
        import json
        payload=json.dumps(payload)

        results = []

        def _decode_dict(a_dict):
            try:
                results.append(a_dict[target_key])
            except KeyError:
                pass
            return a_dict
        json.loads(payload, object_hook=_decode_dict)
        return results

    @classmethod
    def getVendor(self, bssid=None):
        try:
            return self.mac.lookup(bssid)
        except mac_vendor_lookup.VendorNotFoundError:
            return None

    @classmethod
    def getJSONPayload(self):
        import json
        return json.dumps(self.wipenJSONPayload)

    @classmethod
    def periodicJSONPayloadFileWrite(self):
        import time
        try:
            while True:
                if(self.wipenJSONPayload != {} ):
                    print('[-] Performing periodic payload save...')
                    fo = open(self.filename, 'w')
                    fo.write(self.getJSONPayload())
                    fo.close()
                    time.sleep(self.periodic_file_update)
        except Exception as e:
            print('[!] Error updating output file')

    @classmethod
    def writeJSONPayloadFileWrite(self):
        try:
            if(self.wipenJSONPayload != {} ):
                fo = open(self.filename, 'w')
                fo.write(self.getJSONPayload())
                fo.close()
        except Exception as e:
            print('[!] Error updating output file')

    @classmethod
    def checkSSIDExist(self, ssid=None):
        if(ssid in self.wipenJSONPayload):
            print("[-] SSID already in JSON Object, skipping...")
        else:
            self.initialise_SSID_Struct(ssid=ssid,_id=self.get_new_uuid(),_type=wipenParserClass.get_object_type(obj='ssid'))
        return 0

    @classmethod
    def check_SSID_BSSID_Exist(self, ssid=None):
        if( (len(self.wipenJSONPayload[ssid]['bssid']) == 0) ):
            if(self.verbose):
                print('[-] BSSID were not found')
            return False
        else:
            if(self.verbose):
                print('[-] BSSID were found')
            return True

    @classmethod
    def setTargetSSID(self, ssid):
        self.target_ssid = ssid

    @classmethod
    def _enable_SIMILAR_SSID_METADATA_SEARCH(self, status=None):
        try:
            self.enable_similar_ssid_metadata_search = status
            return 0 
        except Exception as e:
            return 1

    @classmethod
    def demask_Hidden_SSID(self, parent_bssid=None, target_bssid=None, packet=None):
        for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
            if(parent_bssid == _known_bssid.get('bssid')):
                for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['similar_bssid']):
                    if(target_bssid == _similar_ssid_bssid.get('bssid')):
                        self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['similar_bssid'][_known_bssid_pos]['ssid'] = packet.info.decode('utf-8')
        return 0

    @classmethod
    def initialise_SSID_Struct(self, ssid=None, _pid=None, _id=None, _sid=[], _type=None):
        self.wipenJSONPayload.update({
                '{}'.format(ssid):{
                    'bssid':[],
                    'similar_ssid':[],
                    'metadata':{
                        '_pid':_pid,
                        '_id':_id,
                        '_sid':_sid,
                        '_type':_type,
                        'starttime':'{}'.format(datetime.now()),
                        'endtime':None
                    }
                }
            })

    @classmethod
    def initialise_SIMILAR_SSID_Struct(self, ssid=None, similar_ssid=None, _pid=None, _id=None, _sid=[], _type=None):
        self.wipenJSONPayload[ssid]['similar_ssid'].append({
            '{}'.format(similar_ssid):{
                'bssid':[],
                'similar_ssid':[],
                'metadata':{
                    '_pid':_pid,
                    '_id':_id,
                    '_sid':_sid,
                    '_type':_type
                }
            }
        })

    @classmethod
    def add_BSSID_Entry(self, payload=None, bssid=None, frequency=None, protocol=None, authentication=None, vendor=None, hidden_ssid=None, _pid=None, _id=None, _sid=[], _type=None):
        return payload.append({
                "bssid":bssid,
                "frequency":frequency,
                "protocol":protocol,
                "authentication":authentication,
                "associated_clients":[],
                "similar_bssid":[],
                "pmkid":None,
                "vendor":vendor,
                "wps":"wps",
                "times_seen":1,
                "hidden_ssid": hidden_ssid,
                'metadata':{
                    '_pid':_pid,
                    '_id':_id,
                    '_sid':_sid,
                    '_type':_type
                }
            })

    @classmethod
    def add_SIMILAR_BSSID_Entry(self, payload=None, ssid=None, known_bssid=None, postion=None, similar_bssid=None, similar_ssid=None, protocol=None, frequency=None, hidden_ssid=None, vendor=None, authentication=None, _pid=None, _id=None, _sid=[], _type=None):
        return payload.append({
                "ssid":similar_ssid,
                "bssid":similar_bssid,
                "protocol":protocol,
                "frequency":frequency,
                "authentication":authentication,
                "vendor":vendor,
                "times_seen":1,
                "hidden_ssid":hidden_ssid,
                'metadata':{
                    '_pid':_pid,
                    '_id':_id,
                    '_sid':_sid,
                    '_type':_type
                }
            })

    @classmethod
    def add_CONNECTED_CLIENTS(self, payload=None, client_addr=None, identity=None, vendor=None, _pid=None, _id=None, _sid=[], _type=None):
        return payload.append({
            'client_addr':client_addr,
            'identities':[],
            'probes':[],
            'vendor':vendor,
            'metadata':{
                '_pid':_pid,
                '_id':_id,
                '_sid':_sid,
                '_type':_type
            }
        })

    @classmethod
    def add_CONNECTED_CLIENTS_PROBES(self, payload=None, probed_ssid=None, _pid=None, _id=None, _sid=[], _type=None):
        return payload.append({
            'probe':probed_ssid,
            'metadata':{
                '_pid':_pid,
                '_id':_id,
                '_sid':_sid,
                '_type':_type
            }
        })

    @classmethod
    def add_CONNECTED_CLIENTS_IDENTITY(self, payload=None, identity=None, _pid=None, _id=None, _sid=[], _type=None):
        return payload.append({
            'identity':identity,
            'metadata':{
                '_pid':_pid,
                '_id':_id,
                '_sid':_sid,
                '_type':_type
            }
        })

    @classmethod
    def update_SSID_BSSID_TIMES_SEEN_Count(self, payload=None):
        return payload.update({'times_seen': payload['times_seen']+1})

    @classmethod
    def update_SSID_ENDTIME(self, ssid=None):
        self.wipenJSONPayload[ssid]['metadata']['endtime'] = '{}'.format(datetime.now())
        return 1

    @classmethod
    def find_SSID_Handler(self, packet):
        ##
        ## This block searches the BSSID broadcasting either the target SSID, or
        ## the similar SSID. Adding the identified BSSID to the list. 
        ##

        import re
        ssid=self.target_ssid

        # Search for target SSID BSSID
        if( (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)) and (packet.addr2 not in self.ignore_bssid) and (packet.info.decode('utf-8') == ssid) ):
            
            if( (packet.addr2 not in self.deep_search(
                target_key='bssid',
                payload=self.wipenJSONPayload[ssid]['bssid'])) ):
                print('[-] Found new BSSID for {}, adding...'.format(ssid))
                self.add_BSSID_Entry(
                    payload=self.wipenJSONPayload[ssid]['bssid'],
                    bssid=packet.addr2,
                    frequency=wipenParserClass.getChannel(packet.getlayer(RadioTap).ChannelFrequency) if(packet.getlayer(RadioTap)) else None,
                    protocol=wipenParserClass.getStandard(standard=packet.getlayer(RadioTap).ChannelFlags, packet=packet) if packet.getlayer(RadioTap) else None,
                    authentication=wipenParserClass.getAuthentication(packet),
                    vendor=self.getVendor(bssid=packet.addr2),
                    hidden_ssid=True if(not packet.info) else False,
                    _pid=self.wipenJSONPayload[ssid]['metadata'].get('_id'),
                    _id=self.get_new_uuid(),
                    _type=wipenParserClass.get_object_type(obj='bssid')
                )
            elif( (packet.addr2 in self.deep_search(
                target_key='bssid',
                payload=self.wipenJSONPayload[ssid]['bssid'])) ):
                if(self.verbose):
                    print('[-] Known BSSID, skipping...')
                for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
                    if(packet.addr2 == _known_bssid.get('bssid')):
                        self.update_SSID_BSSID_TIMES_SEEN_Count(
                            payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]
                        )
            else:
                if(self.verbose):
                    print('[-] Packet did not meet condition, skipping...')
        # search for similar SSID and similar SSID BSSID
        elif( (not self.skip_similar) and 
         (self.ssid_pattern[0] is not None) and (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)) and ( packet.addr3 not in self.ignore_bssid ) and ( packet.info.decode('utf-8') != ssid and packet.info.decode('utf-8') is not None and packet.info.decode('utf-8') != '' ) ):
            for ssid_pattern in self.ssid_pattern:
                if( (re.search(ssid_pattern, packet.info.decode('utf-8'), re.IGNORECASE)) 
                    and (packet.info.decode('utf-8') not in [next(iter(_known_similar_ssid)) for _known_similar_ssid in self.wipenJSONPayload[ssid]['similar_ssid']] ) ):
                    print('[-] New similar SSID found \'{}\' frame, adding...'.format(packet.info.decode('utf-8')))
                    self.initialise_SIMILAR_SSID_Struct(ssid=ssid, similar_ssid=packet.info.decode('utf-8'), _pid=self.wipenJSONPayload[ssid]['metadata'].get('_id'), _id=self.get_new_uuid(), _type=wipenParserClass.get_object_type(obj='ssid'))
                    for _known_similar_ssid_pos, _known_similar_ssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid']):
                        if( (packet.info.decode('utf-8') == next(iter(_known_similar_ssid))) ):
                            self.add_BSSID_Entry(
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'],
                                bssid=packet.addr2,
                                frequency=wipenParserClass.getChannel(packet.getlayer(RadioTap).ChannelFrequency) if(packet.getlayer(RadioTap)) else None,
                                protocol=wipenParserClass.getStandard(standard=packet.getlayer(RadioTap).ChannelFlags, packet=packet) if packet.getlayer(RadioTap) else None,
                                authentication=wipenParserClass.getAuthentication(packet),
                                vendor=self.getVendor(bssid=packet.addr2),
                                hidden_ssid=True if(not packet.info) else False,
                                _pid=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['metadata'].get('_id'),
                                _id=self.get_new_uuid(),
                                _type=wipenParserClass.get_object_type(obj='bssid')
                            )

                        else:
                            pass
                elif( (re.search(ssid_pattern, packet.info.decode('utf-8'), re.IGNORECASE)) 
                    and (packet.info.decode('utf-8') in [next(iter(_known_similar_ssid)) for _known_similar_ssid in self.wipenJSONPayload[ssid]['similar_ssid']] ) ):
                    for _known_similar_ssid_pos, _known_similar_ssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid']):
                        if( (packet.info.decode('utf-8') == next(iter(_known_similar_ssid))) 
                            and (packet.addr2 not in self.deep_search(
                                target_key='bssid',
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid']
                                ) ) 
                        ):
                            print('[-] Adding new BSSID entry for known similar SSID \'{}\''.format(next(iter(_known_similar_ssid))))
                            self.add_BSSID_Entry(
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'],
                                bssid=packet.addr2,
                                frequency=wipenParserClass.getChannel(packet.getlayer(RadioTap).ChannelFrequency) if(packet.getlayer(RadioTap)) else None,
                                protocol=wipenParserClass.getStandard(standard=packet.getlayer(RadioTap).ChannelFlags, packet=packet) if packet.getlayer(RadioTap) else None,
                                authentication=wipenParserClass.getAuthentication(packet),
                                vendor=self.getVendor(bssid=packet.addr2),
                                hidden_ssid=True if(not packet.info) else False,
                                _pid=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['metadata'].get('_id'),
                                _id=self.get_new_uuid(),
                                _type=wipenParserClass.get_object_type(obj='bssid'))
                        elif( (packet.info.decode('utf-8') == next(iter(_known_similar_ssid))) 
                            and (any((match := item) in [packet.addr1, packet.addr2] for item in self.deep_search(
                                target_key='bssid',
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid']
                                ) ) )
                        ):
                            if(self.verbose):
                                print('[-] BSSID {} is already known for similar SSID {}'.format(match, next(iter(_known_similar_ssid))))
                            for _known_similar_ssid_bssid_pos, _known_similar_ssid_bssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid']):
                                if(match == _known_similar_ssid_bssid.get('bssid')):
                                    self.update_SSID_BSSID_TIMES_SEEN_Count(
                                        payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]
                                    )
                        else:
                            if(self.verbose):
                                print('[-] Packet did not meet condition, skipping...')       
                else:
                    if(self.verbose):
                        print('[-] Packet did not meet condition, skipping...')

        else:
            if(self.verbose):
                print('[-] Packet did not meet condition, skipping...')

    @classmethod
    def find_SIMILAR_BSSID_Handler(self, packet):
        try:
            ssid=self.target_ssid

            for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
                if( (self.wipenJSONPayload[ssid]['bssid'] is not []) and (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)) and ( packet.addr2 not in self.ignore_bssid ) and (packet.addr2 != _known_bssid.get('bssid')) ):
                    # remove the bssid deep search here

                    mangled_packet_address = packet.addr3.split(':', self.depth)[:-1]
                    mangled_target_address = _known_bssid.get('bssid').split(':', self.depth)[:-1]
                    if((mangled_packet_address == mangled_target_address) and (packet.addr2 not in self.deep_search(
                        target_key='bssid',
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['similar_bssid']
                        )) ):
                        print('[-] Found a similar BSSID for {}, adding...'.format(ssid))
                        self.add_SIMILAR_BSSID_Entry(
                            payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['similar_bssid'],
                            similar_ssid=None if(not packet.info) else packet.info.decode('utf-8'),
                            similar_bssid=packet.addr3,
                            frequency=wipenParserClass.getChannel(packet.getlayer(RadioTap).ChannelFrequency) if(packet.getlayer(RadioTap)) else None,
                            protocol=wipenParserClass.getStandard(standard=packet.getlayer(RadioTap).ChannelFlags, packet=packet) if packet.getlayer(RadioTap) else None,
                            authentication=wipenParserClass.getAuthentication(packet),
                            vendor=self.getVendor(bssid=packet.addr3),
                            hidden_ssid=True if(not packet.info) else False,
                            _pid=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['metadata'].get('_id'),
                            _id=self.get_new_uuid(),
                            _type=wipenParserClass.get_object_type(obj='bssid')
                        )
                    elif((mangled_packet_address == mangled_target_address) and (packet.addr2 not in self.deep_search(
                        target_key='bssid',
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['similar_bssid']
                        )) ):
                        if(self.verbose):
                            print('[-] Similar BSSID already known, skipping...')
                        for _known_bssid_similiar_bssid_pos, _known_bssid_similiar_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['similar_bssid']):
                            if(packet.addr2 == _known_bssid_similiar_bssid.get('bssid')):
                                self.update_SSID_BSSID_TIMES_SEEN_Count(
                                    payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]
                                )
                    else:
                        if(self.verbose):
                            print('[-] Packet did not meet condition, skipping...')
        except:
            raise

    @classmethod
    def find_Connected_Client_Handler(self,packet=None):
        ssid=self.target_ssid

        if(self.verbose):
            print('[-] Searching for STA connected to known BSSID')
            print('[-] Building runtime list of all known BSSID')
        try:
            if( ( packet.haslayer(Dot11) and (packet.type == 2) ) and ( any((match := item) in [packet.addr1, packet.addr2] for item in self.deep_search(
                    target_key='bssid',
                    payload=self.wipenJSONPayload[ssid]) 
            )) ):
                bssid_address = packet.addr1 if packet.addr1 == match else packet.addr2
                client_address = packet.addr2 if packet.addr1 == match else packet.addr1
                self.find_SSID_BSSID_CONNECTED_CLIENTS(ssid=ssid, packet=packet, bssid_address=bssid_address, client_address=client_address)

        except Exception as e:
            print('[-] packet did not find connected client condition')
            print(packet.show())

        return

    @classmethod
    def find_SSID_BSSID_CONNECTED_CLIENTS(self, ssid=None, packet=None, bssid_address=None, client_address=None):
        for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
            if( bssid_address == _known_bssid.get('bssid') and (client_address not in self.deep_search(
                    target_key='client_addr',
                    payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients']
                ) ) and (client_address != 'ff:ff:ff:ff:ff:ff') ):

                print('[-] Found new client connected to {}\'s \'{}\' BSSID, adding...'.format(ssid, bssid_address))
                try:
                    self.add_CONNECTED_CLIENTS(
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'],
                        client_addr=client_address,
                        vendor=self.getVendor(bssid=client_address),
                        _pid=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['metadata'].get('_id'),
                        _id=self.get_new_uuid(),
                        _type=wipenParserClass.get_object_type(obj='sta')
                    )
                except mac_vendor_lookup.VendorNotFoundError:
                    self.add_CONNECTED_CLIENTS(
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'],
                        client_addr=client_address,
                        vendor=None,
                        _pid=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['metadata'].get('_id'),
                        _id=self.get_new_uuid(),
                        _type=wipenParserClass.get_object_type(obj='sta')
                    )
                return 0
            elif(bssid_address == _known_bssid.get('bssid') and (client_address in self.deep_search(
                    target_key='client_addr',
                    payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients']
                ) ) and (client_address != 'ff:ff:ff:ff:ff:ff') ):
                if(self.verbose):
                    print('[-] Client {} known to be connected to BSSID {}, skipping...'.format(client_address, bssid_address))
                return 0
            else:
                if(self.verbose):
                    print('[-] Packet did not meet condition, skipping...')

        if(self.enable_similar_ssid_metadata_search):
            for _known_similar_ssid_pos, _known_similar_ssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid']):
                for _known_similar_ssid_bssid_pos, _known_similar_ssid_bssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid']):
                    if(bssid_address == _known_similar_ssid_bssid.get('bssid') and (client_address not in self.deep_search(
                        target_key='client_addr',
                        payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients']
                    ) ) and (client_address != 'ff:ff:ff:ff:ff:ff') ):
                        print('[-] Found new client connected to {}\'s \'{}\' BSSID, adding...'.format(next(iter(_known_similar_ssid)), bssid_address))
                        try:
                            self.add_CONNECTED_CLIENTS(
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'],
                                client_addr=client_address,
                                vendor=self.getVendor(bssid=client_address),
                                _pid=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['metadata'].get('_id'),
                                _id=self.get_new_uuid(),
                                _type=wipenParserClass.get_object_type(obj='sta')
                            )
                            return 0
                        except mac_vendor_lookup.VendorNotFoundError:
                            self.add_CONNECTED_CLIENTS(
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'],
                                client_addr=client_address,
                                vendor=None,
                                _pid=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['metadata'].get('_id'),
                                _id=self.get_new_uuid(),
                                _type=wipenParserClass.get_object_type(obj='sta')
                            )
                            return 0
                    elif(bssid_address == _known_similar_ssid_bssid.get('bssid') and (client_address in self.deep_search(
                        target_key='client_addr',
                        payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients']
                    ) ) and (client_address != 'ff:ff:ff:ff:ff:ff') ):
                        if(self.verbose):
                            print('[-] Client {} known to be connected to BSSID {}, skipping...'.format(client_address, bssid_address))
                    else:
                        if(self.verbose):
                            print('[-] Packet did not meet condition, skipping...')

    @classmethod
    def find_Connected_Client_Probe_Handler(self,packet=None):
        ssid=self.target_ssid

        if(self.verbose):
            print('[-] Searching for known connected STA\'s probe requests')
            print('[-] Building runtime list of all known STA')
        try:
            if( ( packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11Beacon) ) and ( any((match := item) in [packet.addr1, packet.addr2] for item in self.deep_search(
                    target_key='client_addr',
                    payload=self.wipenJSONPayload[ssid]) 
            )) ):
                client_address = packet.addr2 if packet.addr2 == match else packet.addr1
                bssid_address = packet.addr1 if packet.addr2 == match else packet.addr2
                self.find_CONNECTED_CLIENTS_PROBES(ssid=ssid, packet=packet, bssid_address=bssid_address, client_address=client_address)

        except Exception as e:
            raise
            exit(0)

    @classmethod
    def find_CONNECTED_CLIENTS_PROBES(self, ssid=None, packet=None, bssid_address=None, client_address=None):
        for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
            for _known_associated_client_pos, _known_associated_client in enumerate(self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients']):
                if( client_address == _known_associated_client.get('client_addr') and (packet.info.decode('utf-8') not in self.deep_search(
                        target_key='probe', 
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['probes']
                    )) and (packet.info.decode('utf-8') != '') ):
                    print('[-] Found new probe for \'{}\' by client \'{}\' connected to {}\'s \'{}\' BSSID, adding...'.format(packet.info.decode('utf-8'), client_address, ssid, _known_bssid.get('bssid')))
                    self.add_CONNECTED_CLIENTS_PROBES(
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['probes'],
                        probed_ssid=packet.info.decode('utf-8'),
                        _pid=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['metadata'].get('_id'),
                        _id=self.get_new_uuid(),
                        _type=wipenParserClass.get_object_type(obj='probe')
                        )
                elif( client_address == _known_associated_client.get('client_addr') and (packet.info.decode('utf-8') in self.deep_search(
                        target_key='probe', 
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['probes']
                    )) and (packet.info.decode('utf-8') != '') ):
                    if(self.verbose):
                        print('[-] Client {} known to be connected to BSSID {} and probing for {}, skipping...'.format(client_address, _known_bssid.get('bssid'), packet.info.decode('utf-8')))
                else:
                    if(self.verbose):
                        print('[-] Packet did not meet condition, skipping...')
        if(self.enable_similar_ssid_metadata_search):
            for _known_similar_ssid_pos, _known_similar_ssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid']):
                for _known_similar_ssid_bssid_pos, _known_similar_ssid_bssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid']):
                    for _known_similar_ssid_bssid_associated_client_pos, _known_similar_ssid_bssid_associated_client in enumerate(self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients']):
                        if( client_address == _known_similar_ssid_bssid_associated_client.get('client_addr') and (packet.info.decode('utf-8') not in self.deep_search(
                            target_key='probe', 
                            payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['probes']
                        )) and (packet.info.decode('utf-8') != '') ):
                            print('[-] Found new probe for \'{}\' by client \'{}\' connected to {}\'s \'{}\' BSSID, adding...'.format(packet.info.decode('utf-8'), client_address, next(iter(_known_similar_ssid)), _known_bssid.get('bssid')))
                            self.add_CONNECTED_CLIENTS_PROBES(
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['probes'],
                                probed_ssid=packet.info.decode('utf-8'),
                                _pid=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['metadata'].get('_id'),
                                _id=self.get_new_uuid(),
                                _type=wipenParserClass.get_object_type(obj='probe')
                                )
                        elif( client_address == _known_similar_ssid_bssid_associated_client.get('client_addr') and (packet.info.decode('utf-8') in self.deep_search(
                            target_key='probe', 
                            payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['probes']
                        )) and (packet.info.decode('utf-8') != '') ):
                            if(self.verbose):
                                print('[-] Client {} known to be connected to BSSID {} and probing for {}, skipping...'.format(client_address, bssid_address, packet.info.decode('utf-8')))
                        else:
                            if(self.verbose):
                                print('[-] Packet did not meet condition, skipping...')
        return

    @classmethod
    def find_Connected_Client_Identity_Handler(self, packet=None):
        ssid=self.target_ssid

        if(self.verbose):
            print('[-] Searching for known connected STA\'s identity responses')
            print('[-] Building runtime list of all known STA')
        try:
            if( ( packet.type == 2 ) and ( packet.haslayer(EAP) and packet.getlayer(EAP).code == 2 ) and (hasattr(packet.getlayer(EAP), 'identity')) and ( any((match := item) in [packet.addr1, packet.addr2] for item in self.deep_search(
                    target_key='client_addr',
                    payload=self.wipenJSONPayload[ssid]) 
            )) and (match not in self.ignore_client) ):
                client_address = packet.addr2 if packet.addr2 == match else packet.addr1
                bssid_address = packet.addr1 if packet.addr2 == match else packet.addr2
                self.find_CONNECTED_CLIENTS_IDENTITY(ssid=ssid, packet=packet, bssid_address=bssid_address, client_address=client_address)

        except Exception as e:
            if(self.verbose):
                print('[-] packet did not meet condition')
                print(packet.show())

        return

    @classmethod
    def find_CONNECTED_CLIENTS_IDENTITY(self, ssid=None, packet=None, bssid_address=None, client_address=None):
        for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
            for _known_associated_client_pos, _known_associated_client in enumerate(self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients']):
                if( (client_address == _known_associated_client.get('client_addr') ) and ( packet.getlayer(EAP).identity.decode('utf-8') not in self.deep_search(
                        target_key='identity', 
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['identities']
                    )) and (bssid_address == _known_bssid.get('bssid')) ):

                    print('[-] Found new identity for \'{}\' by client \'{}\' connected to {}\'s \'{}\' BSSID, adding...'.format(packet.getlayer(EAP).identity.decode('utf-8'), client_address, ssid, bssid_address))
                    self.add_CONNECTED_CLIENTS_IDENTITY(
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['identities'],
                        identity=packet.getlayer(EAP).identity.decode('utf-8'),
                        _pid=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['metadata'].get('_id'),
                        _id=self.get_new_uuid(),
                        _type=wipenParserClass.get_object_type(obj='identity')
                        )
                elif( (client_address == _known_associated_client.get('client_addr') ) and ( packet.getlayer(EAP).identity.decode('utf-8') not in self.deep_search(
                        target_key='identity', 
                        payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos]['associated_clients'][_known_associated_client_pos]['identities']
                    )) ):
                    if(self.verbose):
                        print('[-] Identity {} already known for client {} known to be connected to BSSID {} and probing for {}, skipping...'.format(packet.getlayer(EAP).identity.decode('utf-8'), client_address, bssid_address, packet.info.decode('utf-8')))
                else:
                    if(self.verbose):
                        print('[-] Packet did not meet condition, skipping...')
        if(self.enable_similar_ssid_metadata_search):
            for _known_similar_ssid_pos, _known_similar_ssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid']):
                for _known_similar_ssid_bssid_pos, _known_similar_ssid_bssid in enumerate(self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid']):
                    for _known_similar_ssid_bssid_associated_client_pos, _known_similar_ssid_bssid_associated_client in enumerate(self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients']):
                        if( ( client_address == _known_similar_ssid_bssid_associated_client.get('client_addr') ) and (packet.getlayer(EAP).identity.decode('utf-8') not in self.deep_search(
                            target_key='identity', 
                            payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['identities']
                        )) and (bssid_address == _known_bssid.get('bssid')) ):
                            print('[-] Found new identity for \'{}\' by client \'{}\' connected to {}\'s \'{}\' BSSID, adding...'.format(packet.getlayer(EAP).identity.decode('utf-8'), client_address, next(iter(_known_similar_ssid)), bssid_address))
                            self.add_CONNECTED_CLIENTS_IDENTITY(
                                identity=packet.getlayer(EAP).identity.decode('utf-8'),
                                payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['identities'],
                                _pid=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['metadata'].get('_id'),
                                _id=self.get_new_uuid(),
                                _type=wipenParserClass.get_object_type(obj='identity')
                                )
                        elif( ( client_address == _known_similar_ssid_bssid_associated_client.get('client_addr') ) and (packet.getlayer(EAP).identity.decode('utf-8') in self.deep_search(
                            target_key='identity', 
                            payload=self.wipenJSONPayload[ssid]['similar_ssid'][_known_similar_ssid_pos][next(iter(_known_similar_ssid))]['bssid'][_known_similar_ssid_bssid_pos]['associated_clients'][_known_similar_ssid_bssid_associated_client_pos]['identities']
                        )) ):
                            if(self.verbose):
                                print('[-] Identity {} already known for client {} known to be connected to BSSID {} and probing for {}, skipping...'.format(packet.getlayer(EAP).identity.decode('utf-8'), client_address, bssid_address, packet.info.decode('utf-8')))
                        else:
                            if(self.verbose):
                                print('[-] Packet did not meet condition, skipping...')
        return

    @classmethod
    def find_SSID_BSSID_PMKID(self, packet):
        import binascii

        ssid=self.target_ssid
        if( (packet.haslayer(EAPOL)) and (packet.haslayer(Raw)) and (packet.addr2 in self.deep_search(
                target_key='bssid',
                payload=self.wipenJSONPayload[ssid]['bssid'])) ):
            if( (binascii.hexlify(packet[EAPOL][Raw].load[2:4]) == b'8a00') ):
                print('[-] Found EAPOL message 1 for known BSSID {}, checking for PMKID...'.format(packet.addr2))
                # '000fac04' is the RSN PMKID field
                if( '000fac04' in packet[EAPOL][Raw].load.hex() ):
                    print('[-] PMKID for BSSID {} found!'.format(packet.addr2))
                    index = packet[EAPOL][Raw].load.hex().index('000fac04')
                    pmkid = packet[EAPOL][Raw].load.hex()[index + 8:index+48]
                    
                    for _known_bssid_pos, _known_bssid in enumerate(self.wipenJSONPayload[ssid]['bssid']):
                        if(packet.addr2 == _known_bssid.get('bssid')):
                            self.add_SSID_BSSID_PMKID(
                                payload=self.wipenJSONPayload[ssid]['bssid'][_known_bssid_pos],
                                pmkid=pmkid
                            )
                else:
                    if(self.verbose):
                        print('[-] No PMKID found for BSSID {}')
            else: pass
        else: pass
        return

    @classmethod
    def add_SSID_BSSID_PMKID(self, payload=None, pmkid=None):
        return payload.update({'pmkid':'{}'.format(pmkid)})

    @classmethod
    def find_SSID_BSSID_WPS(self):
        return

    @classmethod
    def add_SSID_BSSID_WPS(self):
        return
