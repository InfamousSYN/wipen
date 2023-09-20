#!/usr/bin/python3
from scapy.all import *
from lib import settings
from lib.parser import wipenParser

class InterfaceManager():

    @classmethod
    def __init__(self, save_pcap=False, output_pcap=None, ssid_scope=None, interface=None, hop_rate=None, capture_length=None, verbose=None, revert_interface=True, filename=None, depth=None, ignore_bssid=None, ignore_client=None, ssid_pattern=None, disable_vendor_mac_refresh=None, periodic_file_update=None, skip_similar=False):
        self.stop_hop = False
        self.save_pcap=save_pcap
        self.output_pcap=output_pcap
        self.interface=interface
        self.verbose=verbose
        self.revert_interface=revert_interface
        self.hop_rate=hop_rate
        self.capture_length=capture_length
        self.channels=[1,2,3,44,5,6,7,8,9,10,11,12,13,14,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161]

        self.ssid_scope=ssid_scope
        self.ssid_pattern=ssid_pattern
        self.filename=filename
        self.depth=depth
        self.ignore_bssid=ignore_bssid
        self.ignore_client=ignore_client
        self.disable_vendor_mac_refresh=disable_vendor_mac_refresh
        self.periodic_file_update=periodic_file_update
        self.skip_similar=skip_similar

    @staticmethod
    def ifaceUp(interface):
        import os
        os.system('ifconfig {} up'.format(interface))
        return

    @staticmethod
    def ifaceDown(interface):
        import os
        os.system('ifconfig {} down'.format(interface))
        return

    @staticmethod
    def testIfaceOpMode(interface):
        import os
        return os.popen('iwconfig {}'.format(interface)).read()

    @staticmethod
    def ifaceMonitor(interface):
        import os
        os.system('iwconfig {} mode monitor'.format(interface))
        return

    @staticmethod
    def ifaceManaged(interface):
        import os
        os.system('iwconfig {} mode managed'.format(interface))
        return

    @staticmethod
    def ifaceChannel(interface, channel):
        import os
        os.system('iwconfig {} channel {}'.format(interface, channel))
        return

    @staticmethod
    def nmcliDisable(interface):
        import os
        try:
            os.system('nmcli device set {} managed no'.format(interface))
        except Exception as e:
            if(self.verbose):
                print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
        return

    @staticmethod
    def nmcliEnable(interface):
        import os
        try:
            os.system('nmcli device set {} managed yes'.format(interface))
        except Exception as e:
            if(self.verbose):
                print('[!]\t\tError:\r\n\t\t\t{}'.format(e))
        return

    @staticmethod
    def testIfaceConMode(interface):
        import os
        return os.popen('nmcli device show {}'.format(interface)).read()

    @classmethod
    def disable_nmcli_interface(self, interface):
        if(self.verbose):
            print('[-]\tDisabling nmcli\'s management of interface: {}'.format(interface))
        self.nmcliDisable(interface=interface)

    @classmethod
    def enable_nmcli_interface(self, interface):
        if(self.verbose):
            print('[-]\tEnabling nmcli\'s management of interface: {}'.format(interface))
        self.nmcliEnable(interface=interface)

    @classmethod
    def check_interface_control_mode(self, interface=None, keyword='unmanaged'):
        res = self.testIfaceConMode(interface=interface)
        for line in res.splitlines():
            if( "GENERAL.STATE:" in line and "{}".format(keyword.lower()) not in line.lower() ):
                return True
            else:
                return False

    @classmethod
    def set_interface_monitor(self, interface):
        if(self.verbose):
            print('[-]\tInterface Mode Toggle: changing \'{}\' mode to \'monitor\''.format(interface))
        self.ifaceDown(interface=interface)
        self.ifaceMonitor(interface=interface)
        self.ifaceUp(interface=interface)

    @classmethod
    def set_interface_managed(self, interface):
        if(self.verbose):
            print('[-]\tInterface Mode Toggle: changing \'{}\' mode to \'managed\''.format(interface))
        self.ifaceDown(interface=interface)
        self.ifaceManaged(interface=interface)
        self.ifaceUp(interface=interface)

    @classmethod
    def check_interface_operational_mode(self, interface, keyword='Monitor'):
        res = self.testIfaceOpMode(interface=interface)
        return True if 'Mode:{}'.format(keyword) in res else False

    @classmethod
    def set_interface_channel(self, interface, channel):
        if(self.verbose):
            print('[-]\tInterface Channel: changing \'{}\' channel to \'{}\''.format(interface, channel))
        self.ifaceChannel(interface=interface, channel=channel)

    @staticmethod
    def getRandomChannel(channels=None):
        import random
        return random.choice(channels)

    @classmethod
    def _continuous_hop(self):
        import time

        while not self.stop_hop:
            self.set_interface_channel(interface=self.interface, channel=self.getRandomChannel(channels=self.channels))
            time.sleep(self.hop_rate)
        return 0

    @classmethod
    def _continuous_sniff(self):
        while not self.stop_hop:
            sniff(iface=self.interface, prn=lambda packet: self._process_packet(packet), store=0, quiet=True)
        return 0

    @classmethod
    def _process_packet(self, packet):
        if(self.save_pcap):
            wrpcap(self.output_pcap, packet, append=True)

        self.parser.find_SSID_Handler(packet=packet)
        self.parser.find_SIMILAR_BSSID_Handler(packet=packet)
        self.parser.find_SIMILAR_SSID_Handler(packet=packet)

        if( self.skip_similar ):
            self.parser._enable_SIMILAR_SSID_METADATA_SEARCH(status=False)
        else:
            self.parser._enable_SIMILAR_SSID_METADATA_SEARCH(status=True)

        self.parser.find_Connected_Client_Handler(packet=packet)
        self.parser.find_Connected_Client_Probe_Handler(packet=packet)
        self.parser.writeJSONPayloadFileWrite()
        return None

    @classmethod
    def _controller(self):
        import threading

        self.parser = wipenParser.wipenParserClass(
            verbose=self.verbose,
            depth=self.depth,
            ssid_pattern=self.ssid_pattern,
            filename=self.filename,
            ignore_bssid=self.ignore_bssid,
            ignore_client=self.ignore_client,
            disable_vendor_mac_refresh=self.disable_vendor_mac_refresh,
            periodic_file_update=self.periodic_file_update,
            )

        for ssid in self.ssid_scope:
            print('[-] Building skeleton JSON Object for \'{}\''.format(ssid))
            self.parser.checkSSIDExist(ssid=ssid)
            self.parser.setTargetSSID(ssid)

        hopping_thread = threading.Thread(target=self._continuous_hop, daemon=True)
        hopping_thread.start()

        sniff_thread = threading.Thread(target=self._continuous_sniff, daemon=True)
        sniff_thread.start()

        hopping_thread.join(self.capture_length)
        if hopping_thread.is_alive():
            self.stop_hop = True
        return 0

    @classmethod
    def main(self):
        print('[-] Checking if network manager is controlling interface: {}'.format(self.interface))
        if( self.check_interface_control_mode(interface=self.interface) ):
            self.disable_nmcli_interface(interface=self.interface)
        else:
            print('[-] interface \'{}\' is already not controlled by network manager'.format(self.interface))
            print('[-] Checking if \'{}\' is in monitor mode'.format(self.interface))
        if(not self.check_interface_operational_mode(interface=self.interface)):
            self.set_interface_monitor(interface=self.interface)
        else:
            print('[-] interface \'{}\' is already in monitor mode'.format(self.interface))
            print('[-] interface is now configured for live capture mode, beginning...')
        if(self._controller() != 0):
            return 1
        if(self.revert_interface):
            self.set_interface_managed(interface=self.interface)
            self.enable_nmcli_interface(interface=self.interface)
            return 0
