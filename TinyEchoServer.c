/*
 *
 *    Copyright 2023 Jay Logue
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *          Implementation for Tiny Echo Server
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "TinyEchoServer.h"

static void memswap(uint8_t * buf1, uint8_t * buf2, size_t len);
static uint16_t UpdateChecksum(uint32_t sum, uint16_t old, uint16_t new);

#define ntoh16(X) (((((X)) << 8) & 0xFF00) | ((((X)) >> 8) & 0xFF))
#define not16(X) ((~(X)) & 0xFFFF)

struct EthernetIPFrame {
    struct {
        uint8_t DestMAC[6]; 
        uint8_t SrcMAC[6]; 
        uint16_t Type;
    } Ethernet;
    union {
        struct {
            uint16_t HTYPE;
            uint16_t PTYPE;
            uint8_t HLEN;
            uint8_t PLEN;
            uint16_t OPER;
            uint8_t SHA[6];
            uint8_t SPA[4];
            uint8_t THA[6];
            uint8_t TPA[4];
        } ARP;
        struct {
            struct {
                uint8_t VersionIHL;
                uint8_t DSCPECN;
                uint16_t TotalLen;
                uint16_t Id;
                uint16_t FlagsFragOffset;
                uint8_t TTL;
                uint8_t Protocol;
                uint16_t Checksum;
                uint8_t SrcAddr[4];
                uint8_t DestAddr[4];
            } Header;
            union {
                struct {
                    struct {
                        uint16_t Type_Code;
                        uint16_t Checksum;
                    } Header;
                    uint8_t Payload[0];
                } ICMP;
                struct {
                    struct {
                        uint16_t SrcPort;
                        uint16_t DestPort;
                        uint16_t Len;
                        uint16_t Checksum;
                    } Header;
                    uint8_t Payload[0];
                } UDP;
            };
        } IP;
    };
} __PACKED;

/** Server IPv4 address (in network byte order) */
uint8_t TinyEchoServer_IPAddress[4] = { 192, 168, 1, 2 };

/** Server Ethernet MAC address */
uint8_t TinyEchoServer_MACAddress[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

/** Process an incoming Ethernet frame and optionally generate a response
 *
 * This function takes as input a buffer containing an Ethernet frame, and a
 * pointer to an integer containing the frame's length.  When presented with an
 * incoming Ethernet frame, the function decodes the frame and determines an
 * appropriate response.  If a response packet is to be sent, the function
 * overwrites the buffer with the contents of the outbound Ethernet frame
 * containing the response and adjusts the frameLen value as necessary.  It then
 * returns true.  On the other hand, if no response should be sent, the function
 * returns false without modifying the input parameters.
 * 
 * Note that the input frame data should begin with the Ethernet header followed
 * by the payload. The input frame length value should count all of the header and
 * payload byte (including any padding), but NOT the bytes of the Frame Check
 * Sequence (FCS) or Inter-packet Gap (IPG).  Likewise, the output length will
 * not include the header and payload, but not the length of the FCS.
 * 
 * The `TinyEchoServer_ProcessEthernetFrame()` function is implemented such that
 * it only requires access to the headers of the input packet, not the full packet
 * data.  This is useful in situations where the Ethernet driver spreads large
 * packets over multiple recieve buffers.  In this case only the first such buffer
 * need be passed to the function.  To ensure all headers are available in the input
 * buffer, the buffer must contain at least the first 42 bytes of the full Ethernet
 * frame. (Also note that, as mentioned above, the frame length variable should
 * contain the length of the entire frame, not just the length of data in the input
 * buffer).
 */
bool TinyEchoServer_ProcessEthernetFrame(uint8_t * frameBuf, uint32_t * frameLen)
{
    struct EthernetIPFrame * frame = (struct EthernetIPFrame *)frameBuf;

    /* Ignore the frame if it is too small */
    if (*frameLen < sizeof(frame->Ethernet)) {
        return false;
    }

    /* If the frame contains an IPv4 packet... */
    if (frame->Ethernet.Type == ntoh16(0x0800)) {

        /* Ignore the frame if it is too small */
        if (*frameLen < (sizeof(frame->Ethernet) + sizeof(frame->IP.Header))) {
            return false;
        }

        /* If the frame contains an ICMP packet... */
        if (frame->IP.Header.Protocol == 1) {

            /* Ignore the frame if it is too small */
            if (*frameLen < (sizeof(frame->Ethernet) + sizeof(frame->IP.Header) + sizeof(frame->IP.ICMP.Header))) {
                return false;
            }

            /* Convert the packet into an ICMP Echo Reply */
            memswap(frame->Ethernet.SrcMAC, frame->Ethernet.DestMAC, 6);
            memswap(frame->IP.Header.SrcAddr, frame->IP.Header.DestAddr, 4);
            frame->IP.ICMP.Header.Type_Code = 0;
            frame->IP.ICMP.Header.Checksum = UpdateChecksum(frame->IP.ICMP.Header.Checksum, 8, 0);

            return true;
        }

        /* If the frame contains a UDP packet... */
        else if (frame->IP.Header.Protocol == 17) {

            /* Ignore the frame if it is too small */
            if (*frameLen < (sizeof(frame->Ethernet) + sizeof(frame->IP.Header) + sizeof(frame->IP.UDP.Header))) {
                return false;
            }

            /* Fail if the destination port is not 7 */
            if (frame->IP.UDP.Header.DestPort != ntoh16(7)) {
                return false;
            }

            /* Convert the packet into a UDP echo reply */
            memswap(frame->Ethernet.SrcMAC, frame->Ethernet.DestMAC, 6);
            memswap(frame->IP.Header.SrcAddr, frame->IP.Header.DestAddr, 4);
            memswap((uint8_t *)&frame->IP.UDP.Header.SrcPort, (uint8_t *)&frame->IP.UDP.Header.DestPort, 2);

            return true;
        }
    
        /* Ignore all other packet types */
        else {
            return false;
        }
    }

    /* If the frame contains an ARP packet... */
    else if (frame->Ethernet.Type == ntoh16(0x0806)) {

        /* Ignore the frame if the length is incorrect */
        if (*frameLen < (sizeof(frame->Ethernet) + sizeof(frame->ARP))) {
            return false;
        }

        /* Ignore the packet if the hardware type is not Ethernet (1) or the 
         * protocol type is not IPv4 (0x0800) */
        if (frame->ARP.HTYPE != ntoh16(1) ||
            frame->ARP.PTYPE != ntoh16(0x0800)) {
            return false;
        }

        /* Ignore the packet if the hardware address length is not 6 or the
         * protocol address length is not 4 */
        if (frame->ARP.HLEN != 6 || frame->ARP.PLEN != 4) {
            return false;
        }

        /* Ignore the packet if the operation type is not Request (1) */
        if (frame->ARP.OPER != ntoh16(1)) {
            return false;
        }

        /* Ignore the packet if the target protocol address is not our IP address */
        if (memcmp(frame->ARP.TPA, TinyEchoServer_IPAddress, 4) != 0) {
            return false;
        }

        /* Change the packet to an ARP response with our MAC address */
        memcpy(frame->Ethernet.DestMAC, frame->Ethernet.SrcMAC, 6);
        memcpy(frame->Ethernet.SrcMAC, TinyEchoServer_MACAddress, 6);
        frame->ARP.OPER = ntoh16(2);
        memcpy(frame->ARP.TPA, frame->ARP.SPA, 4);
        memcpy(frame->ARP.THA, frame->ARP.SHA, 6);
        memcpy(frame->ARP.SPA, TinyEchoServer_IPAddress, 4);
        memcpy(frame->ARP.SHA, TinyEchoServer_MACAddress, 6);

        /* Set the correct frame length */
        *frameLen = sizeof(frame->Ethernet) + sizeof(frame->ARP); 

        return true;
    }

    /* Ignore all other Ethernet frame types */
    else {
        return false;
    }
}

static void memswap(uint8_t * buf1, uint8_t * buf2, size_t len)
{
    for (; len; len--, buf1++, buf2++) {
        uint8_t tmp = *buf2;
        *buf2 = *buf1;
        *buf1 = tmp;
    }
}

static uint16_t UpdateChecksum(uint32_t sum, uint16_t old, uint16_t new)
{
    sum = not16(ntoh16(sum)) + not16(ntoh16(old)) + ntoh16(new);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = not16(sum);
    return (uint16_t)ntoh16(sum);
}
