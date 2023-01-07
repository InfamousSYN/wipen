# wipen
Wipen is an automated tool for extracting information from pcap files created by either using an wireless interface in monitor mode and recording the captured frames using [wireshark](https://www.wireshark.org) or a tool such as `airodump-ng` from the [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng). The goal of `wipen` is to perform target attribution and organise the information in an easily digestable JSON format to aid penetration testing activities and identifying information to report on. 

`wipen` performs multiple passes over the specified PCAP file to parse frames and build the relationships over the interesting information:
1. Search for BSSID broadcasting target SSID
2. performs a search for similar BSSID to known target SSID's BSSID
3. performs a search for similar SSID pattern to target SSID and populate BSSID broadcasting the similar SSID
4. Search for interesting metadata for parent level SSID and for each identified similar SSID per parent level SSID.
 - Map connected STA to known BSSID
  - identify all SSID probed for by connected STA
  - identify all EAP identities sent by connected STA
 - Populate PMKID information for known BSSID ( ON ROADMAP )
 - Populate WPS status ( ON ROADMAP )

By completing multiple parses over the given pcap, the overall memory usage is lower. Additionally, after completing each pass, the JSON object is updated with the results. 

## Usage

### Installation
```
git clone https://github.com/InfamousSYN/wipen
python3 -m install -r wipen/requirements.txt
```

### Usage
```
usage: python3 wipen.py -f example.pcap -s example

automated wireless pcap dissector

options:
  -h, --help            show this help message and exit

General Settings:
  -f PCAP_FILENAME [PCAP_FILENAME ...], --file PCAP_FILENAME [PCAP_FILENAME ...]
                        Provide one or more pcap to analysis
  -o OUTPUT_FILENAME, --output OUTPUT_FILENAME
                        Specify output filename
  -v, --verbose         Enable verbose
  --skip-similar-bssid  Skip searching for similar BSSID
  --skip-similar-ssid   Skip searching for similar SSID
  --show-final          Show final JSON payload
  --threshold PERIODIC_FILE_UPDATE
                        Set periodic update for output file time in minutes (default: 15)

PCAP Parsing Settings:
  -s TARGET_SSID [TARGET_SSID ...], --ssid TARGET_SSID [TARGET_SSID ...]
                        Specify a one ore more SSID to analysis
  --ssid-pattern SSID_PATTERN [SSID_PATTERN ...]
                        Provide one or more possible SSID patterns to search for.
  -I IGNORE_BSSID [IGNORE_BSSID ...], --ignore-bssid IGNORE_BSSID [IGNORE_BSSID ...]
                        Specify one or more BSSID to ignore during the parsing (default: ['00:11:22:33:44:55', 'ff:ff:ff:ff:ff:ff'])
  --ignore-client IGNORE_CLIENT [IGNORE_CLIENT ...]
                        Specify one or more STA addresses to ignore during parsing (default: ['00:11:22:33:44:00'])
  --depth DEPTH         Depth to match the number of fields of a BSSID address (default: 5)
  --disable-vendor-mac-refresh
                        Disable refresh of vendor MAC table refresh (default: False)
```

### Example
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~]
└─$ sudo python3 /opt/wipen/wipen2.py -f [PCAP CAP] --ssid-pattern [P1] [P2] -s [TARGET SSID] -o [OUTFILE] |tee -a [OUTFILE].log
[+] Launching wipen 2.0.0
[-] Start time: 2023-01-07 06:58:46.122309
[-]
[-] Refreshing vendor MAC table list
[-] Building skeleton JSON Object for '[TARGET SSID]'
[-] Saving to file: [TARGET SSID].json
[-] Performing periodic payload save...
[-] Starting runtime job for '[TARGET SSID]'...
[+] Reading file: [PCAP CAP]
[+] Searching for BSSID broadcasting target SSID
[-] Found new BSSID for [TARGET SSID], adding...
[-] Updating [TARGET SSID].json file with results of search for BSSID broadcasting target SSID
[-]
[+] Searching for similar BSSID to known target SSID's BSSID
[-] Found a similar BSSID for [TARGET SSID], adding...
[-] Performing periodic payload save...
[-] Updating [TARGET SSID].json file with results of search for similar BSSID to known target SSID's BSSID
[-]
[+] Searching for similar SSID pattern to target SSID
[-] New similar SSID found '[SSID1]' frame, adding...
[-] New similar SSID found '[SSID2]' frame, adding...
[-] Adding new BSSID entry for known similar SSID '[SSID1]'
[-] New similar SSID found '[SSID3]' frame, adding...
[-] Adding new BSSID entry for known similar SSID '[SSID3]'
[-] New similar SSID found '[SSID4]' frame, adding...
[-] Adding new BSSID entry for known similar SSID '[SSID4]'
[-] Adding new BSSID entry for known similar SSID '[SSID3]'
[-] New similar SSID found '[SSID]' frame, adding...
[-] Performing periodic payload save...

[-] Updating [TARGET SSID].json file with results of search for similar SSID to target SSID
[-]
[-] Enabling searching for similar SSID to target SSID metadata...
[+] Searching for clients connected to known BSSID for target SSID
[-] Found new client connected to [SSID2]'s '00:11:22:33:44:00' BSSID, adding...
[-] Found new client connected to [TARGET SSID]'s '00:22:22:33:44:00' BSSID, adding...
[-] Found new client connected to [SSID2]'s '00:11:22:33:44:00' BSSID, adding...
[-] Performing periodic payload save...
[-] Updating [TARGET SSID].json file with results of connected client search
[-]
[+] Searching for probes from known connected clients
[-] Found new probe for '[SSID4]' by client '00:44:33:22:11:00' connected to [SSID2]'s 'ff:ff:ff:ff:ff:ff' BSSID, adding...
[-] Performing periodic payload save...
[-] Updating [TARGET SSID].json file with results of connected client's probe search
[-]
[+] Searching for EAP identity messages from known connected clients
[-] Found new identity for '[EAP IDENTITY]' by client '00:44:33:22:11:00' connected to [SSID2]'s '00:11:22:33:44:00' BSSID, adding...
[-] Updating [TARGET SSID].json file with results of connected client's identity search
[-]
[-] Ending runtime job for '[TARGET SSID]' and '[PCAP CAP]' task completed
[-] Updating [TARGET SSID].json with final JSON payload for '[TARGET SSID]' and closing
[-]
[-] Final update of [TARGET SSID].json and closing
[-]
[-]
[-] End time: 2023-01-07 07:23:47.003218
[-] Duration: 1500 seconds
[-]

┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~]
└─$ 
```

**REQUIRED:** The input pcap must have the `RadioTap` layer for `wipen` to determine the channel frequency and 802.11 data protocol used by the target SSID. This means, a cap file produced by `[airodump-ng`](https://www.aircrack-ng.org/doku.php?id=airodump-ng) used as the input will not display a frequency or protocol value for any of the BSSID. 

**Note:** When analysising a large pcap file, it is recommended to use `tee` to pipe the STDOUT to a file for logging purposes. 

### Output JSON Object Schema

The JSON object produced by `wipen` will be in the following schema:  

```
{
  "ssid":{
      "bssid":[{
              "bssid":str,
              "frequency":int,
              "protocol":str,
              "authentication":str,
              "associated_clients":[{
                'client_addr':str,
                'identities':[{
                  'id':int,
                  'identity':str
                }],
                'probes':[{
                  'id':int,
                  'probe':str
                }],
                'vendor':str
              }],
              "similar_bssid":[{
                "ssid":str,
                "bssid":str,
                "protocol":str,
                "frequency":int,
                "authentication":str,
                "vendor":str,
                "times_seen":int,
                "hidden_ssid":boolean,
              }],
              "pmkid":[],
              "vendor":str,
              "wps":str,
              "times_seen":int,
              "hidden_ssid":boolean
          }],
      "similar_ssid":[{
        "ssid":{
            "bssid":[{
                    "bssid":str,
                    "frequency":int,
                    "protocol":str,
                    "authentication":str,
                    "associated_clients":[{
                      'client_addr':str,
                      'identities':[{
                        'id':int,
                        'identity':str
                      }],
                      'probes':[{
                        'id':int,
                        'probe':str
                      }],
                      'vendor':str
                    }],
                    "similar_bssid":[{
                      "ssid":str,
                      "bssid":str,
                      "protocol":str,
                      "frequency":int,
                      "authentication":str,
                      "vendor":str,
                      "times_seen":int,
                      "hidden_ssid":boolean,
                    }],
                    "pmkid":[],
                    "vendor":str,
                    "wps":str,
                    "times_seen":int,
                    "hidden_ssid":boolean
                }],
            "similar_ssid":[]
        }
    }]
  }
}
```

### Additional tools
There are addition tools that can support `wipen`, or leverage the produced JSON object. For more information, refer to the tool's [README](https://github.com/InfamousSYN/wipen/tools/README.md) documentation.


## To Do
- Add a task queue system that watches for new content in the json object and then uses workers to perform action. IE When a new BSSID for the parent is added, a worker then opens the pcap and iterates over the packet collection to count the total number of time the BSSID was seen and begins to search for connected clients and other similar BSSID. The number of parallel subtasks being ran at a time is controllable through argparse with a default of 2. 
- look at finding similar ssid based on [`difflib`](https://docs.python.org/2/library/difflib.html)
- detect WEP rather than listing as WPA/PSK
