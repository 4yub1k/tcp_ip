#!/bin/python3

import socket
import argparse
import sys


"""
Before starting please have a look at blue print image of this Packet.
"""


class TcpIp:
    source_ip = "192.168.0.1"       # change
    destination_ip = "192.168.0.1"  # change or use getIp
    source_port = 00                # Decimal = 12336, You can use hex(12336) = 3030
    destination_port = 00           # 16 bit, Decimal = 80, hex = 00 50
    timeout = 5                     # Wait in seconds for response.

    def __init__(self):
        self.program_args()
        try:
            # socket.IPPROTO_TCP for TCP
            self.sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )

            # we are assigning the IP
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except socket.error as err:
            sys.exit(err)

    # -------check sum-----
    def check_sum(self, values, name=None):
        """
        Calculate the checksum value.
        """
        print(name.center(20, "-"))
        sum = 0
        for value in values:
            # ignore this only for representaion in binary
            x = bin(int(value, 16))[2:].zfill(16)
            sum += int(value, 16)
            print(f"0x{value}, {x} --> sum : {hex(sum)}")

        # - Removing Carryover 15912 , we need it in range FFFF #Do it in binary to understand carryover
        # - print(sum,0xFFFF)
        if sum > 0xFFFF:  # - if sum value is greater then 0xFFFF then slice the carry
            carry = hex(sum)[2:3]  # 0x15912 --> slice get 0x[1]5912

        # - print(carry)
        sum = hex(sum)[3:]  # 0x15912 --> 5912 in hex

        # - convert to int base 16 (HEX) and add carryover
        sum = int(sum, 16) + int(carry, 16)
        print(f"\tchecksum: {hex(sum)}, carry: {carry}")  # print Hex and carry
        # - negagtion-- total 0xFFFF as 16 bit
        sum = 0xFFFF - sum  # 0xFFFF-sum
        sum = format(sum, "04x")
        print(f"\tchecksum : {sum}\n")

        return sum  # value 0000 formate

    def ip_to_hex(self, ip):
        # - let ip = 192.168.1.1
        first = ""  # - 192.168 --> 16 bit
        second = ""  # - 1.1 --> 16 bit

        for index, value in enumerate(
            map(int, ip.split("."))
        ):  # - map will change the type from string to int
            # - index start from 0 -> 0,1,2,3
            if index < 2:
                # format always fill remaing with zero upto 2 values, 0x1 --> 01, x for converting to hex.
                first += format(value, "02x") 
            else:
                second += format(value, "02x")

        # returns hex values of ['192168','11']
        return first, second

    def ip(self):
        """
        IP
        """
        version = ("4")          # verion and ihl makes 1 byte, So don't add 0's to it for checksum
        ihl = "5"
        typeOfServices = "00"
        total_length = "0028"    # length of packet in bytes 10 x 4=40 --hex--> 28
        identification = "abcd"  # random hex value, 16 bit
        # - as flag+fragment is 3 & 13 bits so we will can write them combine
        flags = "00"
        fragment_offset = "00"
        ttl = "40"
        self.protocol = "06"
        # - intialize with zero in calculation.
        ip_checksum = "0000"
        self.sourceIP = self.ip_to_hex(self.source_ip)
        self.destIP = self.ip_to_hex(self.destination_ip)

        # ----List of Varibales of IP Checksums----
        # - version + ihl + typeOfServices because the packet is divided into 16 bits. if it was to be divided in 8 bits then version and ihl would be seperated.Follow rules.
        # - See packet format for details

        # - you can also do the same by dividing the sum of all values and then make their 16 bit chunks.
        ip_checksum = [
            version + ihl + typeOfServices,
            total_length,
            identification,
            flags + fragment_offset,
            ttl + self.protocol,
            ip_checksum,
            self.sourceIP[0],
            self.sourceIP[1],
            self.destIP[0],
            self.destIP[1],
        ]

        ip_header = (
            version
            + ihl
            + typeOfServices
            + total_length
            + identification
            + flags
            + fragment_offset
            + ttl
            + self.protocol
            + self.check_sum(ip_checksum, name="IP checksum")
            + self.sourceIP[0]
            + self.sourceIP[1]
            + self.destIP[0]
            + self.destIP[1]
        )
        # print(ip_header)
        ip_hexbytes = bytearray.fromhex(ip_header)

        return ip_header, ip_hexbytes

    def tcp(self):
        """
        TCP
        """
        sourcePort = self.source_port  # 16 bit
        self.destination_port = "0050"  # 16 bit
        seqNumber = "00000000"  # 32 bit
        ackNumber = "00000000"  # 32 bit
        # dataOffset='5' # min=5 ,max value 15 in decimal(the size of the TCP header in 32-bit words)

        # - Normally minimum tcplength is 20 as in our case.
        # - TCP length (including the data part,if any) in byte. #we have no data field.
        tcplength = "0014"  # - 5 x 4= 20 bytes --hex-> 0014

        # reserved='00'

        # flags_1='02'#syn on 000000010 --hex--> 02
        t_drf = "5002"  # combine of (dataoffset, reserved, flag) 16 bit
        windowsize = "7110"  # (flow) here random //window size= bandwidth(Mbits connects) x delay(ms)//you can get it from
        tcpchecksum = "0000"  # if wrong will not work
        urgentPointer = "0000"

        tcp_checksum = [
            self.protocol,
            self.sourceIP[0],
            self.sourceIP[1],
            self.destIP[0],
            self.destIP[1],
            tcplength,
            sourcePort,
            self.destination_port,
            seqNumber,
            ackNumber,
            t_drf,
            windowsize,
            tcpchecksum,
            urgentPointer,
        ]
        tcp_header = (
            sourcePort
            + self.destination_port
            + seqNumber
            + ackNumber
            + t_drf
            + windowsize
            + self.check_sum(tcp_checksum, name="TCP checksum")
            + urgentPointer
        )
        # - bytearray.fromhex(hexstring)-- converts the hex string to bytearray YOU CAN USE encode() also.
        tcp_hexbytes = bytearray.fromhex(tcp_header)

        return tcp_header, tcp_hexbytes

    def print_outputs(self):
        ip_header, ip_hexbytes = self.ip()
        tcp_header, tcp_hexbytes = self.tcp()

        print(f"Source IP : {self.source_ip}\nDestination IP : {self.destination_ip}")
        print(
            f"Source Port : {int(self.source_port, 16)}\nDestination Port : {int(self.destination_port, 16)}\n"
        )

        print("----IP header & bytes----")
        print(f"IP Header : {ip_header}")
        print(f"IP Bytes : {ip_hexbytes}\n")

        print("----TCP header & bytes----")
        print(f"TCP Header : {tcp_header}")
        print(f"TCP Bytes : {tcp_hexbytes}\n")

        # Combined IP/TCP
        packet = ip_hexbytes + tcp_hexbytes

        try:
            print("----Packet Sent----")
            # - ip_header+tcp_header -->packet hex string
            packet_hex = ip_header + tcp_header
            print(f"Packet : {packet_hex}")
            print(f"Packet bytes: {packet}")
            # slice the flag hex from hex string then convert to binary to see the difference
            print(f"TCP flag : {format(int(packet_hex[66:68], 16), '09b')} \n")

            self.sock.settimeout(self.timeout)
            self.sock.sendto(packet, (self.destination_ip, 0))

            print("----Packet Received----")
            received = self.sock.recv(1024)
            received_hex = received.hex()
            print(f"Packet : {received_hex}")
            print(f"Received Bytes: {received}")
            # slice the flag hex from hex string then convert to binary to see the difference
            print(f"TCP flags : {format(int(received_hex[66:68], 16), '09b')}")

        except socket.timeout as timeout:
            sys.exit(timeout)
        except socket.error as err:
            sys.exit(err)

    def program_args(self):
        parser = argparse.ArgumentParser(description="TCP/IP Crafting : GitHub @4yub1k")
        parser.add_argument(
            "-s",
            "--srcip",
            required=True,
            type=str,
            metavar="",
            help="Source Ip address.",
        )
        parser.add_argument(
            "-sp", "--srcport", required=True, type=int, metavar="", help="Source port."
        )
        parser.add_argument(
            "-d",
            "--dstip",
            required=True,
            type=str,
            metavar="",
            help="Destination Ip address.",
        )
        parser.add_argument(
            "-dp",
            "--dstport",
            required=True,
            type=int,
            metavar="",
            help="Destination port.",
        )
        parser.add_argument(
            "-t",
            "--timeout",
            required=False,
            type=int,
            metavar="",
            help="Wait for response.(Default=5 secs)",
        )

        args = parser.parse_args()

        self.source_ip = args.srcip
        self.source_port = hex(args.srcport)[2:]  # Decimal = 12336, You can use hex(12336) = 3030
        self.destination_ip = args.dstip
        self.destination_port = hex(args.dstport)[2:]  # 16 bit, Decimal = 80, hex = 00 50
        if args.timeout:
            self.timeout = args.timeout


if __name__ == "__main__":
    obj = TcpIp()
    obj.print_outputs()
