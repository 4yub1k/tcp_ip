# tcp_ip
Manual crafting TCP/IP\
Change the Soure and Destionation IPS\
__Blue Print Of Packet :__

![ip](https://user-images.githubusercontent.com/45902447/147408122-b0c87a93-dcf8-422d-95b9-442dc8d8e949.jpg)

__Script Outputs:__
```
Checksum Calculations:

Pseudo = Protocol + Source Address (IP) + Destination Address (IP) + TCP length (including the data part) in byte (no actual header field, has to be counted)

Tcp header = Source Port + Destination Port + Sequence Number + Acknowledgement Number + (Data Offset | Reserved | Flags ) + Window Size + Checksum (set to 0x0000 in calculation) + Urgent Pointer

*if value of Tcp header is greater then 0xFFFF then there will be a carry, 0x12345 --> 0x2345 +0x0001 = 0x2346 , This how to compensate carryover.
Total will be 0xFFF - 0x2346
Tcp Header = Tcp header + carryover(if any).

Total Checksum = 0xFFF - ( Pseudo + Tcp header ) , Negation with (0xFFFF)
```
__Checksum TCP :__

![tcp_header](https://user-images.githubusercontent.com/45902447/147408201-d8343e28-54a0-4fe4-b015-e80268f4a629.jpg)

__Checksum IP :__

![iphead](https://user-images.githubusercontent.com/45902447/147408222-5bd081cf-52bf-4d3d-83d9-57323586f9df.jpg)

__Headers :__

![tcp_ip](https://user-images.githubusercontent.com/45902447/147408288-7e04aef5-5e81-433f-ab0c-0cf815b782ad.jpg)
