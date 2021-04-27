# wipen
Wipen is an automated tool used to extract target information from pcap files and organise the information in an easily digestable JSON format to aid penetration testing activities and identifying information to report on. 

## Example
### Usage
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wipen]
└─$ python3 wipen.py -f ../rogue_capture.pcap -s rogue
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
WARNING: can't import layer ipsec: cannot import name 'gcd' from 'fractions' (/usr/lib/python3.9/fractions.py)
[+] Analysing file: ../rogue_capture.pcap
[+] Result of analysis:
{"rogue": {"bssids": [{"bssid": "00:11:22:33:44:00", "source": null, "protocol": "802.11b", "channel": 7, "associated_clients": [{"client_mac": "00:00:00:00:00:01", "probes": ["rogue"]}, {"client_mac": "00:00:00:00:00:02", "probes": ["\u2620\ufe0f\u2620\ufe0f\u2620\ufe0f\u2620\ufe0f\u2620\ufe0f"]}], "similar_bssids": []},{"bssid": "00:11:22:33:44:01", "source": null, "protocol": "802.11b", "channel": 11, "associated_clients": [{"client_mac": "00:00:00:00:00:03", "probes": ["rogue"]}], "similar_bssids": []}]}}
[+] 2320 packets analysed from file: ../rogue_capture.pcap
                                                                                                                                                                                                                                             
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/wipen]
└─$ 
```

### Output
```
{
  "rogue": {
    "bssids": [
      {
        "bssid": "00:11:22:33:44:00",
        "source": null,
        "protocol": "802.11b",
        "channel": 7,
        "associated_clients": [
          {
            "client_mac": "00:00:00:00:00:01",
            "probes": [
              "rogue"
            ]
          },
          {
            "client_mac": "00:00:00:00:00:02",
            "probes": [
              "☠️☠️☠️☠️☠️"
            ]
          }
        ],
        "similar_bssids": []
      },
      {
        "bssid": "00:11:22:33:44:01",
        "source": null,
        "protocol": "802.11b",
        "channel": 11,
        "associated_clients": [
          {
            "client_mac": "00:00:00:00:00:03",
            "probes": [
              "rogue"
            ]
          }
        ],
        "similar_bssids": []
      }
    ]
  }
}
```
