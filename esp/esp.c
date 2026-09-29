/**
 * @file esp.c
 * @brief ESP (IP Encapsulating Security Payload)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneIPSEC Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL ESP_TRACE_LEVEL

//Dependencies
#include "ipsec/ipsec.h"
#include "ipsec/ipsec_inbound.h"
#include "ipsec/ipsec_outbound.h"
#include "ipsec/ipsec_anti_replay.h"
#include "ipsec/ipsec_misc.h"
#include "esp/esp.h"
#include "esp/esp_packet_encrypt.h"
#include "esp/esp_packet_decrypt.h"
#include "core/tcp_fsm.h"
#include "core/raw_socket.h"
#include "ipv4/icmp.h"
#include "debug.h"

//Check IPsec library configuration
#if (ESP_SUPPORT == ENABLED)


/**
 * @brief Protect an outbound IPv4 packet using ESP
 * @param[in] context Pointer to the IPsec context
 * @param[in] sa Pointer to the security association
 * @param[in] interface Underlying network interface
 * @param[in] pseudoHeader IPv4 pseudo header
 * @param[in] fragId Fragment identification field
 * @param[in] buffer Multi-part buffer containing the payload
 * @param[in] offset Offset to the first byte of the payload
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/

error_t espProtectOutboundIpv4Packet(IpsecContext *context, IpsecSadEntry *sa,
   NetInterface *interface, const Ipv4PseudoHeader *pseudoHeader,
   uint16_t fragId, NetBuffer *buffer, size_t offset,
   NetTxAncillary *ancillary)
{
   error_t error;
   size_t n;
   size_t length;
   size_t offset2;
   NetBuffer *buffer2;
   Ipv4PseudoHeader pseudoHeader2;
   EspHeader *espHeader;

   //Retrieve the length of the data
   length = netBufferGetLength(buffer) - offset;

   //The sender may add 0 to 255 bytes of padding
   n = espComputePadLength(sa, length);
   //Calculate the overhead caused by ESP encryption
   n += sizeof(EspHeader) + sizeof(EspTrailer) + sa->ivLen + sa->icvLen;

#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
   //UDP encapsulation of IPsec ESP packets?
   if(sa->udpEncapsulation)
   {
      //Calculate the overhead caused by UDP encapsulation
      n += sizeof(UdpHeader);
   }
#endif

   //Check the length of the resulting ESP packet
   if((length + n) > ESP_BUFFER_SIZE)
      return ERROR_FAILURE;

#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
   //UDP encapsulation of IPsec ESP packets?
   if(sa->udpEncapsulation)
   {
      //The ESP header is inserted after the UDP header and before the next
      //layer protocol header (transport mode) or before an encapsulated IP
      //header (tunnel mode)
      espHeader = (EspHeader *) (context->buffer + sizeof(UdpHeader));
   }
   else
#endif
   {
      //The ESP header is inserted after the IP header and before the next
      //layer protocol header (transport mode) or before an encapsulated IP
      //header (tunnel mode)
      espHeader = (EspHeader *) context->buffer;
   }

   //The sender increments the sequence number counter for this SA and inserts
   //the low-order 32 bits of the value into the Sequence Number field (refer
   //to RFC 4303, section 3.3.3)
   sa->seqNum++;

   //Format ESP header
   espHeader->spi = htonl(sa->spi);
   espHeader->seqNum = htonl(sa->seqNum);

   //Debug message
   TRACE_INFO("ESP Header:\r\n");
   //Dump ESP header contents for debugging purpose
   espDumpHeader(espHeader);

   //Copy the payload data to be encrypted
   netBufferRead(espHeader->payloadData + sa->ivLen, buffer, offset, length);

   //The encryption algorithm employed to protect the ESP packet is specified
   //by the SA via which the packet is transmitted
   error = espEncryptPacket(context, sa, espHeader, espHeader->payloadData,
      &length, pseudoHeader->protocol);
   //Any error to report?
   if(error)
      return error;

   //Calculate the length of the resulting ESP packet
   length += sizeof(EspHeader);

#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
   //UDP encapsulation of IPsec ESP packets?
   if(sa->udpEncapsulation)
   {
      UdpHeader *udpHeader;

      //An 8-byte UDP header is inserted between the IP header and the ESP
      //header of the ESP packet
      length += sizeof(UdpHeader);

      //Point to the UDP header
      udpHeader = (UdpHeader *) context->buffer;
      
      //Format the UDP header
      udpHeader->srcPort = HTONS(IPSEC_NAT_PORT);
      udpHeader->destPort = HTONS(IPSEC_NAT_PORT);
      udpHeader->length = htons(length);

      //IPv4 UDP Checksum should be transmitted as a zero value
      udpHeader->checksum = HTONS(0);

      //Debug message
      TRACE_INFO("UDP Header:\r\n");
      //Dump UDP header contents for debugging purpose
      udpDumpHeader(udpHeader);
   }
#endif

   //Allocate a buffer to hold the ESP packet
   buffer2 = ipAllocBuffer(length, &offset2);
   //Failed to allocate memory?
   if(buffer2 == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the resulting ESP packet
   netBufferWrite(buffer2, offset2, context->buffer, length);

   //Fix the pseudo header
   pseudoHeader2 = *pseudoHeader;
   pseudoHeader2.length = htonl(length);

#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
   //UDP encapsulation of IPsec ESP packets?
   if(sa->udpEncapsulation)
   {
      //The outer IPv4 protocol header that immediately precedes the UDP header
      //shall contain the value 17 in its Protocol field
      pseudoHeader2.protocol = IPV4_PROTOCOL_UDP;
   }
   else
#endif
   {
      //The outer IPv4 protocol header that immediately precedes the ESP header
      //shall contain the value 50 in its Protocol field (refer to RFC 4303,
      //section 2)
      pseudoHeader2.protocol = IPV4_PROTOCOL_ESP;
   }

   //Send ESP packet
   error = ipsecSendIpv4Packet(interface, &pseudoHeader2, fragId, buffer2,
      offset2, ancillary);

   //Free previously allocated memory
   netBufferFree(buffer2);

   //Return status code
   return error;
}


/**
 * @brief Process ESP protected packet
 * @param[in] interface Underlying network interface
 * @param[in] ipv4Header Pointer to the IPv4 header
 * @param[in] buffer Multi-part buffer containing the ESP protected packet
 * @param[in] offset Offset to the first byte of the ESP header
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @param[in] udpEncapsulation UDP-encapsulated ESP packet
 * @return Error code
 **/

error_t espProcessInboundIpv4Packet(NetInterface *interface,
   const Ipv4Header *ipv4Header, const NetBuffer *buffer, size_t offset,
   NetRxAncillary *ancillary, bool_t udpEncapsulation)
{
   error_t error;
   size_t length;
   uint64_t seq;
   uint8_t nextHeader;
   size_t offset2;
   NetBuffer *buffer2;
   IpsecContext *context;
   IpsecSadEntry *sa;
   EspHeader *espHeader;
   IpsecSelector selector;
   IpPseudoHeader pseudoHeader;

   //Point to the IPsec context
   context = interface->netContext->ipsecContext;
   //Sanity check
   if(context == NULL)
      return ERROR_FAILURE;

   //Retrieve the length of the packet
   length = netBufferGetLength(buffer) - offset;

#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
   //UDP-encapsulated ESP packet?
   if(udpEncapsulation)
   {
      const UdpHeader *udpHeader;

      //Point to the UDP header
      udpHeader = netBufferAt(buffer, offset, sizeof(UdpHeader));
      //Malformed UDP datagram?
      if(udpHeader == NULL)
         return ERROR_FAILURE;

      //Debug message
      TRACE_INFO("Parsing UDP header...\r\n");
      //Dump UDP header contents for debugging purpose
      udpDumpHeader(udpHeader);

      //Make sure the length field is correct
      if(ntohs(udpHeader->length) < sizeof(UdpHeader) ||
         ntohs(udpHeader->length) > length)
      {
         return ERROR_INVALID_HEADER;
      }

      //Convert the length field from network byte order
      length = ntohs(udpHeader->length);

      //Point to the payload data
      offset += sizeof(UdpHeader);
      length -= sizeof(UdpHeader);
   }
#endif

   //Malformed ESP packet?
   if(length < sizeof(EspHeader))
      return ERROR_INVALID_HEADER;

   //Point to the ESP header
   espHeader = netBufferAt(buffer, offset, sizeof(EspHeader));
   //Malformed ESP packet?
   if(espHeader == NULL)
      return ERROR_FAILURE;

   //Debug message
   TRACE_INFO("Parsing ESP header...\r\n");
   //Dump ESP header contents for debugging purpose
   espDumpHeader(espHeader);

   //Upon receipt of a packet containing an ESP Header, the receiver determines
   //the appropriate (unidirectional) SA via lookup in the SAD (refer to
   //RFC 4303, section 3.4.2)
   sa = ipsecFindInboundSadEntry(context, IPSEC_PROTOCOL_ESP,
      ntohl(espHeader->spi));

   //If no valid Security Association exists for this packet the receiver
   //must discard the packet. This is an auditable event
   if(sa == NULL)
   {
      //Debug message
      TRACE_WARNING("ESP: No matching SA found!\r\n");
      //Report an error
      return ERROR_POLICY_FAILURE;
   }

   //Check IPsec mode
   if(sa->mode == IPSEC_MODE_TRANSPORT)
   {
      //Transport mode ESP is applied only to whole IP datagrams (not to IP
      //fragments)
      if((ntohs(ipv4Header->fragmentOffset) & IPV4_OFFSET_MASK) != 0 ||
         (ntohs(ipv4Header->fragmentOffset) & IPV4_FLAG_MF) != 0)
      {
         return ERROR_INVALID_HEADER;
      }
   }
   else
   {
      //In tunnel mode, ESP is applied to an IP packet, which may be a fragment
      //of an IP datagram
   }

   //Because only the low-order 32 bits are transmitted with the packet, the
   //receiver must deduce and track the sequence number subspace into which
   //each packet falls
   seq = ipsecGetSeqNum(sa, ntohl(espHeader->seqNum));

   //For each received packet, the receiver must verify that the packet
   //contains a Sequence Number that does not duplicate the Sequence Number of
   //any other packets received during the life of this SA. This should be the
   //first ESP check applied to a packet after it has been matched to an SA, to
   //speed rejection of duplicate packets (refer to RFC 4303, section 3.4.3)
   error = ipsecCheckReplayWindow(sa, seq);

   //Duplicate packets are rejected
   if(error)
   {
      //Debug message
      TRACE_WARNING("ESP: Invalid sequence number!\r\n");
      //Report an error
      return ERROR_WRONG_SEQUENCE_NUMBER;
   }

   //Point to the payload data
   offset += sizeof(EspHeader);
   length -= sizeof(EspHeader);

   //Check the length of the payload data
   if(length > ESP_BUFFER_SIZE)
      return ERROR_INVALID_LENGTH;

   //Copy the payload data to be decrypted
   netBufferRead(context->buffer, buffer, offset, length);

   //if a separate integrity algorithm is employed, then the receiver proceeds
   //to integrity verification, then decryption. If a combined mode algorithm
   //is employed, the integrity check is performed along with decryption
   error = espDecryptPacket(context, sa, espHeader, context->buffer, &length,
      &nextHeader);

   //If the integrity check fails, the receiver must discard the received IP
   //datagram as invalid. This is an auditable event
   if(error)
   {
      //Debug message
      TRACE_WARNING("ESP: ICV validation failed!\r\n");
      //Report an error
      return ERROR_AUTHENTICATION_FAILED;
   }

   //The receive window is updated only if the ICV verification succeeds
   ipsecUpdateReplayWindow(sa, seq);

   //Allocate a buffer to hold the decrypted payload
   buffer2 = ipAllocBuffer(length, &offset2);
   //Failed to allocate memory?
   if(buffer2 == NULL)
      return ERROR_OUT_OF_MEMORY;

   //Copy the resulting data
   netBufferWrite(buffer2, offset2, context->buffer, length);

   //Retrieve packet's selector
   error = ipsecGetInboundIpv4PacketSelector(ipv4Header, nextHeader, buffer2,
      offset2, &selector);

   //Check status code
   if(!error)
   {
      //Match the packet against the inbound selectors identified by the SAD
      //entry to verify that the received packet is appropriate for the SA via
      //which it was received (refer to RFC 4301, section 5.2)
      if(ipsecIsSubsetSelector(&selector, &sa->selector))
      {
         //Form the IPv4 pseudo header
         pseudoHeader.length = sizeof(Ipv4PseudoHeader);
         pseudoHeader.ipv4Data.srcAddr = ipv4Header->srcAddr;
         pseudoHeader.ipv4Data.destAddr = ipv4Header->destAddr;
         pseudoHeader.ipv4Data.reserved = 0;
         pseudoHeader.ipv4Data.protocol = nextHeader;
         pseudoHeader.ipv4Data.length = htons(length);

#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
         //When a transport mode has been used to transmit packets, contained
         //TCP or UDP headers will have incorrect checksums due to the change
         //of parts of the IP header during transit (refer to RFC 3948,
         //section 3.1.2)
         if(udpEncapsulation && sa->mode == IPSEC_MODE_TRANSPORT)
         {
            ancillary->ignoreTcpChecksum = TRUE;
            ancillary->ignoreUdpChecksum = TRUE;
         }
#endif
         //If the computed and received ICVs match, then the datagram is valid,
         //and it is accepted (refer to RFC 4303, section 3.4.4.1)
         error = ipv4DispatchDatagram(interface, &pseudoHeader, buffer2, offset2,
            ancillary);
      }
      else
      {
         //If an IPsec system receives an inbound packet on an SA and the
         //packet's header fields are not consistent with the selectors for
         //the SA, it must discard the packet. This is an auditable event
         error = ERROR_POLICY_FAILURE;
      }
   }

   //Free previously allocated memory
   netBufferFree(buffer2);

   //Return status code
   return error;
}


/**
 * @brief Determine if a packet uses UDP-encapsulated ESP format
 * @param[in] buffer Multi-part buffer containing the UDP packet
 * @param[in] offset Offset to the first byte of the UDP header
 **/

bool_t espIsUdpEncapsulatedPacket(const NetBuffer *buffer, size_t offset)
{
#if (ESP_UDP_ENCAPS_SUPPORT == ENABLED)
   const UdpHeader *udpHeader;
   const EspHeader *espHeader;

   //Point to the UDP header
   udpHeader = netBufferAt(buffer, offset, sizeof(UdpHeader));
   //Malformed UDP datagram?
   if(udpHeader == NULL)
      return FALSE;

   //The destination port must be the same as that used by IKE traffic (refer
   //to RFC 3948, section 2.1)
   if(ntohs(udpHeader->destPort) != IPSEC_NAT_PORT)
      return FALSE;

   //Point to the ESP header
   espHeader = netBufferAt(buffer, offset + sizeof(UdpHeader),
      sizeof(EspHeader));
   //Malformed ESP packet?
   if(espHeader == NULL)
      return FALSE;

   //The SPI field in the ESP header must not be a zero value (refer to
   //RFC 3948, section 2.1)
   if(espHeader->spi == 0)
      return FALSE;

   //Valid UDP-encapsulated ESP packet
   return TRUE;
#else
   //Not implemented
   return FALSE;
#endif
}


/**
 * @brief Dump ESP header for debugging purpose
 * @param[in] espHeader Pointer to the ESP header
 **/

void espDumpHeader(const EspHeader *espHeader)
{
   //Dump ESP header contents
   TRACE_DEBUG("  SPI = 0x%08" PRIX32 "\r\n", ntohl(espHeader->spi));
   TRACE_DEBUG("  Sequence Number = 0x%08" PRIX32 "\r\n", ntohl(espHeader->seqNum));
}

#endif
