#!/usr/bin/python3
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

from scapy.all import *
from lib import settings
from lib import options as o
from lib import wipenInterfaceManager
from lib.parser import wipenParser
import logging
import queue
import threading
import json
from datetime import datetime

def printError(e):
    print('[!] Error:\r\n{}'.format(e))
    return 0

def writeJSONPayload(payload=None, filename=None):
    fo = open(filename, 'w')
    fo.write(payload)
    fo.close()
    return 0

if __name__ == '__main__':
    try:
        option = o.wipenOptionClass.setOptions()
        if option == 1:
            raise
    except Exception as e:
        printError(e)
        exit(1)
    
    starttime = datetime.now()
    print('[+] Launching wipen {}\r\n[-] Start time: {}\r\n[-]'.format(settings.__version__, starttime))

    if(option['mode'] == 0):
        wipenInterfaceManager.InterfaceManager(
            ssid_scope=option['target_ssid'], 
            ssid_pattern=option['ssid_pattern'],
            filename='{}.json'.format(option['output_filename']),
            depth=option['depth'],
            ignore_bssid=option['ignore_bssid'],
            ignore_client=option['ignore_client'],
            disable_vendor_mac_refresh=option['disable_vendor_mac_refresh'],
            periodic_file_update=option['periodic_file_update'],
            interface=option['interface'], 
            hop_rate=option['hop_rate'], 
            capture_length=option['capture_length'], 
            save_pcap=option['save_pcap'], 
            output_pcap=option['output_pcap'], 
            verbose=option['verbose'],
            skip_similar=option['skip_similar'],
            reverse_bssid=option['reverse_bssid'],
        ).main()
    elif(option['mode'] == 1):
        filename = '{}.json'.format(option['output_filename'])
        wipen = wipenParser.wipenParserClass(
            verbose=option['verbose'],
            depth=option['depth'],
            ssid_pattern=option['ssid_pattern'],
            filename=filename,
            ignore_bssid=option['ignore_bssid'],
            ignore_client=option['ignore_client'],
            disable_vendor_mac_refresh=option['disable_vendor_mac_refresh'],
            periodic_file_update=option['periodic_file_update'],
            skip_similar=option['skip_similar'],
            reverse_bssid=option['reverse_bssid'],
        )
    
        # add each SSID in the runtime list to the JSON payload object
        for ssid in option['target_ssid']:
            print('[-] Building skeleton JSON Object for \'{}\''.format(ssid))
            wipen.checkSSIDExist(ssid=ssid)
        if(option['verbose']):
            print('[-] SSID runtime search list is:\r\n    {}'.format(json.loads(wipen.getJSONPayload())))
            print(wipen.getJSONPayload())
    
        print('[-] Saving to file: {}'.format(filename))
        writeJSONPayload(
            payload=wipen.getJSONPayload(),
            filename=filename)
    
        print('[-] Starting runtime job for \'{}\'...'.format(ssid))
        for ssid in [ssid for index, ssid in enumerate(json.loads(wipen.getJSONPayload()))]:
            wipen.setTargetSSID(ssid)
            for pcap_file in option['pcap_filename']:
                print('[+] Reading file: {}'.format(pcap_file))
    
                print('[+] Searching for BSSID broadcasting target SSID')
                sniff(offline=pcap_file, prn=wipen.find_SSID_Handler, store=0)
                print('[-] Updating {} file with results of search for BSSID broadcasting target SSID\r\n[-]'.format(filename))
                writeJSONPayload(
                    payload=wipen.getJSONPayload(),
                    filename=filename)
    
                if( (not wipen.check_SSID_BSSID_Exist(ssid=ssid)) ):
                    if(option['verbose']):
                        print('[-] No BSSID broadcasting target SSID found')
                    print('[-] No BSSID broadcasting target SSID were found, skipping searching for similar BSSID to known BSSID...')
                    print('[-] Updating {} file with results of search for BSSID broadcasting target SSID\r\n[-]'.format(filename))
                    writeJSONPayload(
                        payload=wipen.getJSONPayload(),
                        filename=filename)
                else:
                    if( (option['skip_similar']) ):
                        print('[-] Searching for similar BSSID to BSSID broadcasting target SSID manually disabled...')
                    else:
                        print('[+] Searching for similar BSSID to known target SSID\'s BSSID')
                        sniff(offline=pcap_file, prn=wipen.find_SIMILAR_BSSID_Handler, store=0)
                        print('[-] Updating {} file with results of search for similar BSSID to known target SSID\'s BSSID\r\n[-]'.format(filename))
                        writeJSONPayload(
                            payload=wipen.getJSONPayload(),
                            filename=filename)
    
                if( (option['skip_similar']) ):
                    print('[-] Disabling searching for similar SSID to target SSID metadata...')
                    wipen._enable_SIMILAR_SSID_METADATA_SEARCH(status=False)
                else:
                    print('[-] Enabling searching for similar SSID to target SSID metadata...')
                    wipen._enable_SIMILAR_SSID_METADATA_SEARCH(status=True)
    
                print('[+] Searching for clients connected to known BSSID for target SSID')
                sniff(offline=pcap_file, prn=wipen.find_Connected_Client_Handler, store=0)
                print('[-] Updating {} file with results of connected client search\r\n[-]'.format(filename))
                writeJSONPayload(
                    payload=wipen.getJSONPayload(),
                    filename=filename)
    
                print('[+] Searching for probes from known connected clients')
                sniff(offline=pcap_file, prn=wipen.find_Connected_Client_Probe_Handler, store=0)
                print('[-] Updating {} file with results of connected client\'s probe search\r\n[-]'.format(filename))
                writeJSONPayload(
                    payload=wipen.getJSONPayload(),
                    filename=filename)
    
                print('[+] Searching for EAP identity messages from known connected clients')
                sniff(offline=pcap_file, prn=wipen.find_Connected_Client_Identity_Handler, store=0)
                print('[-] Updating {} file with results of connected client\'s identity search\r\n[-]'.format(filename))
                writeJSONPayload(
                    payload=wipen.getJSONPayload(),
                    filename=filename)

                print('[+] Searching for PMKID from known BSSID')
                sniff(offline=pcap_file, prn=wipen.find_SSID_BSSID_PMKID, store=0)
                print('[-] Updating {} file with results of PMKID search\r\n[-]'.format(filename))
                writeJSONPayload(
                    payload=wipen.getJSONPayload(),
                    filename=filename)

                print('[-] Ending runtime job for \'{}\' and \'{}\' task completed'.format(ssid, pcap_file))
                print('[-] Updating {} with final JSON payload for \'{}\' and closing\r\n[-]'.format(filename, ssid))
                writeJSONPayload(
                    payload=wipen.getJSONPayload(),
                    filename=filename)
    
        print('[-] Final update of {} and closing\r\n[-]'.format(filename))
        wipen.update_SSID_ENDTIME(ssid=ssid)
        writeJSONPayload(
            payload=wipen.getJSONPayload(),
            filename=filename)
    else:
        print('[!] Unknown packet extraction mode selected')
        sys.exit(1)
    if(option['show_final']):
        print('[-] Result:\r\n    {}'.format(json.loads(wipen.getJSONPayload())))

    endtime = datetime.now()
    print('[-]\r\n[-] End time: {}'.format(endtime))
    print('[-] Duration: {} seconds\r\n[-]'.format((endtime-starttime).seconds))
    sys.exit(0)
