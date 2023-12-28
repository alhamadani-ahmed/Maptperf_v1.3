/* Maptperf is an RFC 8219 compliant MAP-T BR tester written in C++ using DPDK
 *
 *  Copyright (C) 2023 Ahmed Al-hamadani & Gabor Lencse
 *
 *  This file is part of Maptperf.
 *
 *  Maptperf is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Maptperf is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Maptperf.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "defines.h"
#include "includes.h"
#include "throughput.h"
#include "latency.h"

// the understanding of this code requires the knowledge of throughput.c
// only a few functions are redefined or added here

// after reading the parameters for throughput measurement, further two parameters are read
int Latency::readCmdLine(int argc, const char *argv[])
{
  if (Throughput::readCmdLine(argc - 2, argv) < 0)
    return -1;
  if (sscanf(argv[7], "%hu", &first_tagged_delay) != 1 || first_tagged_delay < 0 || first_tagged_delay > 3600)
  {
    std::cerr << "Input Error: Delay before timestamps must be between 0 and 3600." << std::endl;
    return -1;
  }
  if (test_duration <= first_tagged_delay)
  {
    std::cerr << "Input Error: Test test_duration MUST be longer than the delay before the first tagged frame." << std::endl;
    return -1;
  }
  if (sscanf(argv[8], "%hu", &num_of_tagged) != 1 || num_of_tagged < 1 || num_of_tagged > 50000)
  {
    std::cerr << "Input Error: Number of tagged frames must be between 1 and 50000." << std::endl;
    return -1;
  }
  if ((test_duration - first_tagged_delay) * frame_rate < num_of_tagged)
  {
    std::cerr << "Input Error: There are not enough test frames in the (test_duration-first_tagged_delay) interval to be tagged." << std::endl;
    return -1;
  }
  return 0;
}

int Latency::senderPoolSize()
{
  return Throughput::senderPoolSize() + num_of_tagged; // tagged frames are also pre-generated
}

// creates a special IPv4 Test Frame tagged for latency measurement using several helper functions
struct rte_mbuf *mkLatencyFrame4(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                                 const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                                 const uint32_t *src_ip, uint32_t *dst_ip, unsigned var_sport, unsigned var_dport, uint16_t id)
{
  struct rte_mbuf *pkt_mbuf = rte_pktmbuf_alloc(pkt_pool); // message buffer for the Latency Frame
  if (!pkt_mbuf)
    rte_exit(EXIT_FAILURE, "Error: %s sender can't allocate a new mbuf for the Latency Frame! \n", direction);
  length -= ETHER_CRC_LEN;                                                                                       // exclude CRC from the frame length
  pkt_mbuf->pkt_len = pkt_mbuf->data_len = length;                                                               // set the length in both places
  uint8_t *pkt = rte_pktmbuf_mtod(pkt_mbuf, uint8_t *);                                                          // Access the Test Frame in the message buffer
  ether_hdr *eth_hdr = reinterpret_cast<struct ether_hdr *>(pkt);                                                // Ethernet header
  ipv4_hdr *ip_hdr = reinterpret_cast<ipv4_hdr *>(pkt + sizeof(ether_hdr));                                      // IPv4 header
  udp_hdr *udp_hd = reinterpret_cast<udp_hdr *>(pkt + sizeof(ether_hdr) + sizeof(ipv4_hdr));                     // UDP header
  uint8_t *udp_data = reinterpret_cast<uint8_t *>(pkt + sizeof(ether_hdr) + sizeof(ipv4_hdr) + sizeof(udp_hdr)); // UDP data

  mkEthHeader(eth_hdr, dst_mac, src_mac, 0x0800); // contains an IPv4 packet
  int ip_length = length - sizeof(ether_hdr);
  mkIpv4Header(ip_hdr, ip_length, src_ip, dst_ip); // Does not set IPv4 header checksum
  int udp_length = ip_length - sizeof(ipv4_hdr);   // No IP Options are used
  mkUdpHeader(udp_hd, udp_length, var_sport, var_dport);
  int data_length = udp_length - sizeof(udp_hdr);
  mkDataLatency(udp_data, data_length, id);
  udp_hd->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hd); // UDP checksum is calculated and set
  ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr); // IPv4 header checksum is also calculated and set
  return pkt_mbuf;
}

// creates a special IPv6 Test Frame tagged for latency measurement using several helper functions
struct rte_mbuf *mkLatencyFrame6(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                                 const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                                 struct in6_addr *src_ip, struct in6_addr *dst_ip, unsigned var_sport, unsigned var_dport, uint16_t id)
{
  struct rte_mbuf *pkt_mbuf = rte_pktmbuf_alloc(pkt_pool); // message buffer for the Latency Frame
  if (!pkt_mbuf)
    rte_exit(EXIT_FAILURE, "Error: %s sender can't allocate a new mbuf for the Latency Frame! \n", direction);
  length -= ETHER_CRC_LEN;                                                                                       // exclude CRC from the frame length
  pkt_mbuf->pkt_len = pkt_mbuf->data_len = length;                                                               // set the length in both places
  uint8_t *pkt = rte_pktmbuf_mtod(pkt_mbuf, uint8_t *);                                                          // Access the Test Frame in the message buffer
  ether_hdr *eth_hdr = reinterpret_cast<struct ether_hdr *>(pkt);                                                // Ethernet header
  ipv6_hdr *ip_hdr = reinterpret_cast<ipv6_hdr *>(pkt + sizeof(ether_hdr));                                      // IPv6 header
  udp_hdr *udp_hd = reinterpret_cast<udp_hdr *>(pkt + sizeof(ether_hdr) + sizeof(ipv6_hdr));                     // UDP header
  uint8_t *udp_data = reinterpret_cast<uint8_t *>(pkt + sizeof(ether_hdr) + sizeof(ipv6_hdr) + sizeof(udp_hdr)); // UDP data

  mkEthHeader(eth_hdr, dst_mac, src_mac, 0x86DD); // contains an IPv6 packet
  int ip_length = length - sizeof(ether_hdr);
  mkIpv6Header(ip_hdr, ip_length, src_ip, dst_ip);
  int udp_length = ip_length - sizeof(ipv6_hdr); // No IP Options are used
  mkUdpHeader(udp_hd, udp_length, var_sport, var_dport);
  int data_length = udp_length - sizeof(udp_hdr);
  mkDataLatency(udp_data, data_length, id);
  udp_hd->dgram_cksum = rte_ipv6_udptcp_cksum(ip_hdr, udp_hd); // UDP checksum is calculated and set
  return pkt_mbuf;
}

// fills the data field of the Latency Frame
void mkDataLatency(uint8_t *data, uint16_t length, uint16_t latency_frame_id)
{
  unsigned i;
  uint8_t identify[8] = {'I', 'd', 'e', 'n', 't', 'i', 'f', 'y'}; // Identificion of the Latency Frames
  uint64_t *id = (uint64_t *)identify;
  *(uint64_t *)data = *id;
  data += 8;
  length -= 8;
  *(uint16_t *)data = latency_frame_id;
  data += 2;
  length -= 2;
  for (i = 0; i < length; i++)
    data[i] = i % 256;
}

// sends Test Frames for latency measurements including "num_of_tagged" number of Latency frames
int sendLatency(void *par)
{
  // collecting input parameters:
  class senderParametersLatency *p = (class senderParametersLatency *)par;
  class senderCommonParametersLatency *cp = (class senderCommonParametersLatency *)p->cp;

  // parameters directly correspond to the data members of class Throughput
  uint16_t ipv6_frame_size = cp->ipv6_frame_size;
  uint16_t ipv4_frame_size = cp->ipv4_frame_size;
  uint32_t frame_rate = cp->frame_rate;
  uint16_t test_duration = cp->test_duration;
  uint32_t n = cp->n;
  uint32_t m = cp->m;
  uint64_t hz = cp->hz;
  uint64_t start_tsc = cp->start_tsc;
  uint32_t num_of_CEs = cp->num_of_CEs;
  uint16_t num_of_port_sets = cp->num_of_port_sets;
  uint16_t num_of_ports = cp->num_of_ports;
  struct in6_addr *tester_l_ipv6 = cp->tester_l_ipv6;
  uint32_t *tester_r_ipv4 = cp->tester_r_ipv4;
  struct in6_addr *dmr_ipv6 = cp->dmr_ipv6;
  struct in6_addr *tester_r_ipv6 = cp->tester_r_ipv6;
  uint16_t bg_dport_min = cp->bg_dport_min; 
  uint16_t bg_dport_max = cp->bg_dport_max; 
  uint16_t bg_sport_min = cp->bg_sport_min; 
  uint16_t bg_sport_max = cp->bg_sport_max;

  // parameters directly correspond to the data members of class Latency
  uint16_t first_tagged_delay = cp->first_tagged_delay;
  uint16_t num_of_tagged = cp->num_of_tagged;

  // parameters which are different for the Left sender and the Right sender
  rte_mempool *pkt_pool = p->pkt_pool;
  uint8_t eth_id = p->eth_id;
  const char *direction = p->direction;
  CE_data *CE_array = p->CE_array;
  struct ether_addr *dst_mac = p->dst_mac;
  struct ether_addr *src_mac = p->src_mac;
  unsigned var_sport = p->var_sport;
  unsigned var_dport = p->var_dport;
  uint16_t preconfigured_port_min = p->preconfigured_port_min;
  uint16_t preconfigured_port_max = p->preconfigured_port_max;

  uint64_t *send_ts = p->send_ts;

  // further local variables
  uint64_t frames_to_send = test_duration * frame_rate; // Each active sender sends this number of frames
  uint64_t sent_frames = 0;                             // counts the number of sent frames
  double elapsed_seconds;                               // for checking the elapsed seconds during sending

  // temperoray initial IP addresses that will be put in the template packets and they will be changed later in the sending loop
  // useful to calculate correct checksums 
  //(more specifically, the uncomplemented checksum start value after calculating it by the DPDK rte_ipv4_cksum(), rte_ipv4_udptcp_cksum(), and rte_ipv6_udptcp_cksum() functions
  // when creating the template packets)
  uint32_t zero_dst_ipv4;
  struct in6_addr zero_src_ipv6;
  
  // the dst_ipv4 must initially be "0.0.0.0" in order for the ipv4 header checksum to be calculated correctly by The rte_ipv4_cksum() 
  // and for the udp checksum to be calculated correctly the rte_ipv4_udptcp_cksum()
 // and consequently calculate correct checksums in the mKTestFrame4()
  if (inet_pton(AF_INET, "0.0.0.0", reinterpret_cast<void *>(&zero_dst_ipv4)) != 1)
  {
    std::cerr << "Input Error: Bad virt_dst_ipv4 address." << std::endl;
    return -1;
  }

  // the src_ipv6 must initially be "::" for the udp checksum to be calculated correctly by the rte_ipv6_udptcp_cksum
  // and consequently calculate correct checksum in the mKTestFrame6()
  if (inet_pton(AF_INET6, "::", reinterpret_cast<void *>(&zero_src_ipv6)) != 1)
  {
    std::cerr << "Input Error: Bad  virt_src_ipv6 address." << std::endl;
    return -1;
  }
  
  // These addresses are for the foreground traffic in the reverse direction
  // setting the source ipv4 address of the reverse direction to the ipv4 address of the tester right interface
  uint32_t *src_ipv4 = tester_r_ipv4;// This would be set without change during testing in the reverse direction.
                                       // It will represent the ipv4 address of the right interface of the Tester
  *src_ipv4 = htonl(*src_ipv4);
  
  uint32_t *dst_ipv4 = &zero_dst_ipv4; // This would be variable during testing in the reverse direction.
                                       // It will represent the simulated CE (BMR-ipv4-prefix + suffix)
                                       // and is merely specified inside the sending loop using the CE_array

  // These addresses are for the foreground traffic in the forward direction
  struct in6_addr *src_ipv6 = &zero_src_ipv6; // This would be variable during testing in the forward direction.
                                              // It will represent the simulated CE (MAP address) 
                                              //and is merely specified inside the sending loop using the CE_array
                                               
  struct in6_addr *dst_ipv6 = dmr_ipv6; // This would be set without change during testing in the forward direction.
                                        // It will represent the DMR IPv6 address.

  // These addresses are for the background traffic only
  struct in6_addr *src_bg = (direction == "forward" ? tester_l_ipv6 : tester_r_ipv6);  
  struct in6_addr *dst_bg = (direction == "forward" ? tester_r_ipv6 : tester_l_ipv6); 
  
  uint16_t sport_min, sport_max, dport_min, dport_max; // worker port range variables
  
// set the relevant ranges to the wide range prespecified in the configuration file (usually comply with RFC 4814)
// the other ranges that are not set now. They will be set in the sending loop because they are based on the PSID of the
//pseudorandomly enumerated CE
  if (direction == "reverse")
    {
      sport_min = preconfigured_port_min;
      sport_max = preconfigured_port_max;
    }
  else //forward
    {
      dport_min = preconfigured_port_min;
      dport_max = preconfigured_port_max;
    }
  
  // check whether the CE array is built or not
   if(!CE_array)
    rte_exit(EXIT_FAILURE,"No CE array can be accessed by the %s sender",direction);
    
    int latency_test_time = test_duration - first_tagged_delay;                   // lenght of the time interval, while latency frames are sent
  uint64_t frames_to_send_during_latency_test = latency_test_time * frame_rate; // precalcalculated value to speed up calculation in the loop

  // implementation of varying port numbers recommended by RFC 4814 https://tools.ietf.org/html/rfc4814#section-4.5
  // RFC 4814 requires pseudorandom port numbers, increasing and decreasing ones are our additional, non-stantard solutions
  // always one of the same N pre-prepared foreground or background frames is updated and sent,
  // except latency frames, which are stored in an array and updated only once, thus no N copies are necessary
  // source and/or destination IP addresses and port number(s), and UDP and IPv4 header checksum are updated
  // as for foreground or background frames, N size arrays are used to resolve the write after send problem
 
  //some worker variables
  int i;                                                       // cycle variable for the above mentioned purpose: takes {0..N-1} values
  int current_CE;                                              // index variable to the current simulated CE in the CE_array
  uint16_t psid;                                               // Temporary variable for the ID of the randomly selected port set for the simulated CE
  struct rte_mbuf *fg_pkt_mbuf[N], *bg_pkt_mbuf[N], *pkt_mbuf; // message buffers for fg. and bg. Test Frames
  uint8_t *pkt;                                                // working pointer to the current frame (in the message buffer)
  
  //IP Workers
  uint32_t *fg_dst_ipv4[N];
  struct in6_addr *fg_src_ipv6[N];
  struct in6_addr *bg_src_ipv6[N], *bg_dst_ipv6[N];
  uint16_t *fg_ipv4_chksum[N]; 

  //UDP Workers
  uint16_t *fg_udp_sport[N], *fg_udp_dport[N], *fg_udp_chksum[N], *bg_udp_sport[N], *bg_udp_dport[N], *bg_udp_chksum[N]; // pointers to the given fields
  uint16_t *udp_sport, *udp_dport, *udp_chksum;      // working pointers to the given field
  
  uint16_t fg_udp_chksum_start, bg_udp_chksum_start, fg_ipv4_chksum_start; // starting values (uncomplemented checksums taken from the original frames)
  uint32_t chksum = 0; // temporary variable for UDP checksum calculation
  uint32_t ip_chksum = 0; //temporary variable for IPv4 header checksum calculation
  uint16_t sport, dport, bg_sport, bg_dport; // values of source and destination port numbers -- to be preserved, when increase or decrease is done
  uint16_t sp, dp;                           // values of source and destination port numbers -- temporary values

  //same for latency frames
  struct rte_mbuf *lat_fg_pkt_mbuf[num_of_tagged], *lat_bg_pkt_mbuf[num_of_tagged];
  uint32_t *lat_fg_dst_ipv4[num_of_tagged];
  struct in6_addr *lat_fg_src_ipv6[num_of_tagged];
  struct in6_addr *lat_bg_src_ipv6[num_of_tagged], *lat_bg_dst_ipv6[num_of_tagged];
  uint16_t *lat_fg_udp_sport[num_of_tagged], *lat_fg_udp_dport[num_of_tagged], *lat_fg_udp_chksum[num_of_tagged], *lat_bg_udp_sport[num_of_tagged], *lat_bg_udp_dport[num_of_tagged], *lat_bg_udp_chksum[num_of_tagged]; // pointers to the given fields
  uint16_t *lat_fg_ipv4_chksum[num_of_tagged];
  uint16_t lat_fg_ipv4_chksum_start; // starting values (uncomplemented IPv4 header checksum taken from the original frames)
  uint16_t lat_fg_udp_chksum_start[num_of_tagged], lat_bg_udp_chksum_start[num_of_tagged];// The uncomplemented checksum of each latency frame is different because of the unique ID
  
  
  // creating buffers of template test frames
  for (i = 0; i < N; i++)
  {
    // create a foreground Test Frame
    if (direction == "reverse")
    {

      fg_pkt_mbuf[i] = mkTestFrame4(ipv4_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv4, dst_ipv4, var_sport, var_dport);
      pkt = rte_pktmbuf_mtod(fg_pkt_mbuf[i], uint8_t *); // Access the Test Frame in the message buffer
      // the source ipv4 address will not be manipulated as it will permenantly be the tester-right-ipv4
      fg_ipv4_chksum[i] = (uint16_t *)(pkt + 24);
      fg_dst_ipv4[i] = (uint32_t *)(pkt + 30); // The destination ipv4 should be manipulated in the sending loop as it will be the BMR-ipv4-prefix + suffix (i.e. changing each time) in the reverse direction
      // The source address will not be manipulated as it will permentantly be the IP address of the right interface of the Tester (as done in the initilization above)
      fg_udp_sport[i] = (uint16_t *)(pkt + 34);
      fg_udp_dport[i] = (uint16_t *)(pkt + 36);
      fg_udp_chksum[i] = (uint16_t *)(pkt + 40);
    }
    else
    { //"forward"
      fg_pkt_mbuf[i] = mkTestFrame6(ipv6_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv6, dst_ipv6, var_sport, var_dport);
      pkt = rte_pktmbuf_mtod(fg_pkt_mbuf[i], uint8_t *); // Access the Test Frame in the message buffer
      fg_src_ipv6[i] = (struct in6_addr *)(pkt + 22);    // The source address should be manipulated as it will be the MAP address (i.e. changing each time) in the forward direction
      // The destination address will not be manipulated as it will permenantly be the DMR IPv6 address(as done in the initilization above)
      fg_udp_sport[i] = (uint16_t *)(pkt + 54);
      fg_udp_dport[i] = (uint16_t *)(pkt + 56);
      fg_udp_chksum[i] = (uint16_t *)(pkt + 60);
    }
    // Always create a backround Test Frame (it is always an IPv6 frame) regardless of the direction of the test
    // The source and destination IP addresses of the packet have already been set in the initialization above
    // and they will permenantely be the IP addresses of the left and right interfaces of the Tester 
    // and based on the direction of the test 
    bg_pkt_mbuf[i] = mkTestFrame6(ipv6_frame_size, pkt_pool, direction, dst_mac, src_mac, src_bg, dst_bg, var_sport, var_dport);
    pkt = rte_pktmbuf_mtod(bg_pkt_mbuf[i], uint8_t *); // Access the Test Frame in the message buffer
    bg_udp_sport[i] = (uint16_t *)(pkt + 54);
    bg_udp_dport[i] = (uint16_t *)(pkt + 56);
    bg_udp_chksum[i] = (uint16_t *)(pkt + 60);
  }

  //save the uncomplemented UDP checksum value (same for all values of [i]). So, [0] is enough
  fg_udp_chksum_start = ~*fg_udp_chksum[0]; // for the foreground frames 
  bg_udp_chksum_start = ~*bg_udp_chksum[0]; // same but for the background frames
  
  // save the uncomplementd IPv4 header checksum (same for all values of [i]). So, [0] is enough
  if (direction == "reverse") // in case of foreground IPv4 only
      fg_ipv4_chksum_start = ~*fg_ipv4_chksum[0]; 

  // create Latency Test Frames (may be foreground frames and background frames as well)
  struct rte_mbuf **latency_frames = new struct rte_mbuf *[num_of_tagged];
  if (!latency_frames)
    rte_exit(EXIT_FAILURE, "Error: Tester can't allocate memory for latency frame pointers!\n");

  uint64_t start_latency_frame = first_tagged_delay * frame_rate; // the ordinal number of the very first latency frame
  
  for (int i = 0; i < num_of_tagged; i++)
    if ((start_latency_frame + i * frame_rate * latency_test_time / num_of_tagged) % n < m)
    {
      // foreground latency frame, may be IPv4 or IPv6
      if (direction == "reverse")
      {
        latency_frames[i] = mkLatencyFrame4(ipv4_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv4, dst_ipv4, var_sport, var_dport, i);
        pkt = rte_pktmbuf_mtod(latency_frames[i], uint8_t *); // Access the Test Frame in the message buffer
        // the source ipv4 address will not be manipulated as it will permenantly be the tester-right-ipv4
        lat_fg_ipv4_chksum[i] = (uint16_t *)(pkt + 24);
        //~*lat_fg_ipv4_chksum[i] is the same for all values of [i], but it is put here to avoid any segmentation fault if the condition above will always be FALSE.
        lat_fg_ipv4_chksum_start = ~*lat_fg_ipv4_chksum[i];
        lat_fg_dst_ipv4[i] = (uint32_t *)(pkt + 30); // The destination ipv4 should be manipulated in the sending loop as it will be the BMR-ipv4-prefix + suffix (i.e. changine each time)
        // The source address will not be manipulated as it will permentantly be the IP address of the right interface of the Tester (as done in the initilization above)
        lat_fg_udp_sport[i] = (uint16_t *)(pkt + 34);
        lat_fg_udp_dport[i] = (uint16_t *)(pkt + 36);
        lat_fg_udp_chksum[i] = (uint16_t *)(pkt + 40);
      }
      else
      { // "forward"
        latency_frames[i] = mkLatencyFrame6(ipv6_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv6, dst_ipv6, var_sport, var_dport, i);
        pkt = rte_pktmbuf_mtod(latency_frames[i], uint8_t *); // Access the Test Frame in the message buffer
        lat_fg_src_ipv6[i] = (struct in6_addr *)(pkt + 22);   // The source address should be manipulated as it will be the MAP address (i.e. changing each time)
        // The destination address will not be manipulated as it will permenantly be the dmr-ipv6 (as done in the initilization above)
        lat_fg_udp_sport[i] = (uint16_t *)(pkt + 54);
        lat_fg_udp_dport[i] = (uint16_t *)(pkt + 56);
        lat_fg_udp_chksum[i] = (uint16_t *)(pkt + 60);
      }
      lat_fg_udp_chksum_start[i] = ~*lat_fg_udp_chksum[i]; // save the uncomplemented UDP checksum value (different for all values of "i")
    }
    else
    {
      // background frame, must be IPv6
      latency_frames[i] = mkLatencyFrame6(ipv6_frame_size, pkt_pool, direction, dst_mac, src_mac, src_bg, dst_bg, var_sport, var_dport, i);
      pkt = rte_pktmbuf_mtod(latency_frames[i], uint8_t *); // Access the Test Frame in the message buffer
      lat_bg_udp_sport[i] = (uint16_t *)(pkt + 54);
      lat_bg_udp_dport[i] = (uint16_t *)(pkt + 56);
      lat_bg_udp_chksum[i] = (uint16_t *)(pkt + 60);
      lat_bg_udp_chksum_start[i] = ~*lat_bg_udp_chksum[i]; // save the uncomplemented UDP checksum value (different for all values of "i")
    }

    
  // arrays to store the minimum and maximum possible souce and destination port numbers in each port set.
  uint16_t sport_min_for_ps[num_of_port_sets], sport_max_for_ps[num_of_port_sets], dport_min_for_ps[num_of_port_sets], dport_max_for_ps[num_of_port_sets];

  // arrays of indices to know the current source and destination port numbers for each port set, to be used in case of incrementing or decrementing
  uint16_t curr_sport_for_ps[num_of_port_sets]; // used to restore the last used sport in the port set to set the next sport to.
  uint16_t curr_dport_for_ps[num_of_port_sets]; // used to restore the last used dport in the port set to set the next dport to.
  uint16_t curr_sport_for_bg, curr_dport_for_bg; // used to restore the last used port in the background traffic in case the sport or dport are modified in the range of a port set

  for (i = 0; i < num_of_port_sets; i++)
  {
    // set the port boundaries for each port set
    sport_min_for_ps[i] = (uint16_t)(i * num_of_ports);
    sport_max_for_ps[i] = (uint16_t)((i + 1) * num_of_ports) - 1;

    dport_min_for_ps[i] = (uint16_t)(i * num_of_ports);
    dport_max_for_ps[i] = (uint16_t)((i + 1) * num_of_ports) - 1;

    // set the initial values of port numbers for each port set, depending whether they will be increased or decreased
    if (var_sport == 1)
      curr_sport_for_ps[i] = sport_min_for_ps[i];
    if (var_dport == 1)
      curr_dport_for_ps[i] = dport_min_for_ps[i];
    if (var_sport == 2)
      curr_sport_for_ps[i] = sport_max_for_ps[i];
    if (var_dport == 2)
      curr_dport_for_ps[i] = dport_max_for_ps[i];
  }

 // The sport and dport values are initialized according to wide range of values.
  // However, for the foreground packets, in the forward direction, the sport_min and sport_max will be set later in the sending loop based on the generated PSID
  // in the reverse direction, the dport_min and dport_max will be set later in the sending loop based on the generated PSID
  // No change for bg_sport and bg_dport in case of the background packets.
  if (var_sport == 1)
  {
    sport = sport_min;
    bg_sport = bg_sport_min;
  }
  if (var_sport == 2)
  {
    sport = sport_max;
    bg_sport = bg_sport_max;
  }
  if (var_dport == 1)
  {
    dport = dport_min;
    bg_dport = bg_dport_min;
  }
  if (var_dport == 2)
  {
    dport = dport_max;
    bg_dport = bg_dport_max;
  }

  i = 0; // increase maunally after each sending of a normal Test Frame
  current_CE = 0; // increase maunally after each sending

  int latency_timestamp_no = 0;                           // counter for the latency frames from 0 to num_of_tagged-1
  uint64_t send_next_latency_frame = start_latency_frame; // at what frame count to send the next latency frame

  // prepare random number infrastructure
  thread_local std::random_device rd_sport;           // Will be used to obtain a seed for the random number engines
  thread_local std::mt19937_64 gen_sport(rd_sport()); // Standard 64-bit mersenne_twister_engine seeded with rd()
  thread_local std::random_device rd_dport;           // Will be used to obtain a seed for the random number engines
  thread_local std::mt19937_64 gen_dport(rd_dport()); // Standard 64-bit mersenne_twister_engine seeded with rd()

  // naive sender version: it is simple and fast
  for (sent_frames = 0; sent_frames < frames_to_send; sent_frames++)
  { // Main cycle for the number of frames to send
    // set the temporary variables (including several pointers) to handle the right pre-generated Test Frame
    
    if (unlikely(sent_frames == send_next_latency_frame))
    {
      // a latency frame is to be sent

      if (sent_frames % n < m)
      {
        // foreground latency frame is to be sent

        psid = CE_array[current_CE].psid;
        // The uncomplemented checksum of each latency packet is different because there is a unique identifier for each latency packet
        // This is why there is no checksum_start variable that stores the uncomplemented checksum as done with the normal test frames
        // But, we should restore the uncomplemented checksum for each packet in the sending loop
        chksum = lat_fg_udp_chksum_start[latency_timestamp_no]; // restore the uncomplemented UDP checksum of this latency packet to add the values of the varying fields
        udp_sport = lat_fg_udp_sport[latency_timestamp_no];
        udp_dport = lat_fg_udp_dport[latency_timestamp_no];
        udp_chksum = lat_fg_udp_chksum[latency_timestamp_no];
        pkt_mbuf = latency_frames[latency_timestamp_no];

        if (direction == "forward")
        {

          *lat_fg_src_ipv6[latency_timestamp_no] = CE_array[current_CE].map_addr; // set it with the map address
          chksum += CE_array[current_CE].map_addr_chksum;                         // and add its checksum to the UDP checksum

          // the sport_min and sport_max will be set according to the port range values of the selected port set and the sport will retrieve its last value within this range
          // the dport_min and dport_max will remain on thier default values within the wide range. The dport will be changed based on its value from the last cycle.
          sport_min = sport_min_for_ps[psid];
          sport_max = sport_max_for_ps[psid];
          if (var_sport == 1 || var_sport == 2)
            sport = curr_sport_for_ps[psid]; // restore the last used sport in the ps to start over from it (useful when increment or decrement; useless when random)
        }

        if (direction == "reverse")
        {
          ip_chksum = lat_fg_ipv4_chksum_start; // restore the uncomplemented IPv4 header checksum to add the checksum value of the destination IPv4 address
                                                
          *lat_fg_dst_ipv4[latency_timestamp_no] = CE_array[current_CE].ipv4_addr; //set it with the CE's IPv4 address
          
          chksum += CE_array[current_CE].ipv4_addr_chksum; //add its chechsum to the UDP checksum
          ip_chksum += CE_array[current_CE].ipv4_addr_chksum; //and to the IPv4 header checksum

          ip_chksum = ((ip_chksum & 0xffff0000) >> 16) + (ip_chksum & 0xffff); // calculate 16-bit one's complement sum
          ip_chksum = ((ip_chksum & 0xffff0000) >> 16) + (ip_chksum & 0xffff); // Twice is enough
          ip_chksum = (~ip_chksum) & 0xffff;                                   // make one's complement
          if (ip_chksum == 0)                                                  // checksum should not be 0 (0 means, no checksum is used)
            ip_chksum = 0xffff;
          *lat_fg_ipv4_chksum[latency_timestamp_no] = (uint16_t)ip_chksum; //now set the IPv4 header checksum of the packet

          // the dport_min and dport_max will be set according to the port range values of the selected port set and the dport will retrieve its last value within this range
          // the sport_min and sport_max will remain on thier default values within the wide range. The sport will be changed based on its value from the last cycle.
          dport_min = dport_min_for_ps[psid];
          dport_max = dport_max_for_ps[psid];
          if (var_dport == 1 || var_dport == 2)
            dport = curr_dport_for_ps[psid]; // restore the last used dport in the ps to start over from it (useful when increment or decrement; useless when random)
        }
        
      }
      else
      {
        // background latency frame is to be sent
        // from here, we need to handle the background frame identified by the temporary variables

        // same thing about the different uncomplemented checkusm for each background frames
        chksum = lat_bg_udp_chksum_start[latency_timestamp_no]; // restore the value of the uncomplemented checksum of this latency frame to add the values of the varying fields
        udp_sport = lat_bg_udp_sport[latency_timestamp_no];
        udp_dport = lat_bg_udp_dport[latency_timestamp_no];
        udp_chksum = lat_bg_udp_chksum[latency_timestamp_no];
        pkt_mbuf = latency_frames[latency_timestamp_no];
      }
    }
    else
    {
      // normal test frame is to be sent
      
    if (sent_frames % n < m)
    {
      // foreground frame is to be sent

      psid = CE_array[current_CE].psid;
      chksum = fg_udp_chksum_start; // restore the uncomplemented UDP checksum to add the values of the varying fields
      udp_sport = fg_udp_sport[i];
      udp_dport = fg_udp_dport[i];
      udp_chksum = fg_udp_chksum[i];
      pkt_mbuf = fg_pkt_mbuf[i];

      if (direction == "forward")
      {

        *fg_src_ipv6[i] = CE_array[current_CE].map_addr; // set it with the map address
        chksum += CE_array[current_CE].map_addr_chksum;  // and add its checksum to the UDP checksum

        // the sport_min and sport_max will be set according to the port range values of the selected port set and the sport will retrieve its last value within this range
        // the dport_min and dport_max will remain on thier default values within the wide range. The dport will be changed based on its value from the last cycle.
        sport_min = sport_min_for_ps[psid];
        sport_max = sport_max_for_ps[psid];
        if (var_sport == 1 || var_sport == 2)
          sport = curr_sport_for_ps[psid]; // restore the last used sport in the port set to start over from it (useful when increment or decrement; useless when random)
      }

      if (direction == "reverse")
      {
        ip_chksum = fg_ipv4_chksum_start; // restore the uncomplemented IPv4 header checksum to add the checksum value of the destination IPv4 address

        *fg_dst_ipv4[i] = CE_array[current_CE].ipv4_addr; //set it with the CE's IPv4 address

        chksum += CE_array[current_CE].ipv4_addr_chksum; //add its chechsum to the UDP checksum
        ip_chksum += CE_array[current_CE].ipv4_addr_chksum; //and to the IPv4 header checksum

        ip_chksum = ((ip_chksum & 0xffff0000) >> 16) + (ip_chksum & 0xffff); // calculate 16-bit one's complement sum
        ip_chksum = ((ip_chksum & 0xffff0000) >> 16) + (ip_chksum & 0xffff); // Twice is enough
        ip_chksum = (~ip_chksum) & 0xffff;                                   // make one's complement
        if (ip_chksum == 0)                                                  // checksum should not be 0 (0 means, no checksum is used)
          ip_chksum = 0xffff;
        *fg_ipv4_chksum[i] = (uint16_t)ip_chksum; //now set the IPv4 header checksum of the packet

        // the dport_min and dport_max will be set according to the port range values of the selected port set and the dport will retrieve its last value within this range
        // the sport_min and sport_max will remain on thier default values within the wide range. The sport will be changed based on its value from the last cycle.
        dport_min = dport_min_for_ps[psid];
        dport_max = dport_max_for_ps[psid];
        if (var_dport == 1 || var_dport == 2)
          dport = curr_dport_for_ps[psid]; // restore the last used dport in the ps to start over from it (useful when increment or decrement; useless when random)
      }
      }
      else
      {
        // background frame is to be sent
        // from here, we need to handle the background frame identified by the temporary variables

        chksum = bg_udp_chksum_start; // restore the uncomplemented UDP checksum to add the values of the varying fields
        udp_sport = bg_udp_sport[i];
        udp_dport = bg_udp_dport[i];
        udp_chksum = bg_udp_chksum[i];
        pkt_mbuf = bg_pkt_mbuf[i];
      }
    }
        
    if (sent_frames % n < m) // normal or latency frames
    { // foreground
        // Change the value of the source and destination port numbers
        if (var_sport)
        {
          // sport is varying
          switch (var_sport)
          {
          case 1: // increasing port numbers
            if ((sp = sport++) == sport_max)
              sport = sport_min;
            break;
          case 2: // decreasing port numbers
            if ((sp = sport--) == sport_min)
              sport = sport_max;
            break;
          case 3: // pseudorandom port numbers
            std::uniform_int_distribution<int> uni_dis_sport(sport_min, sport_max); // uniform distribution in [sport_min, sport_max]
            sp = uni_dis_sport(gen_sport);
          }
          *udp_sport = htons(sp); // set the source port 
          chksum += *udp_sport; // and add it to the UDP checksum
        }
        if (var_dport)
        {
          // dport is varying
          switch (var_dport)
          {
          case 1: // increasing port numbers
            if ((dp = dport++) == dport_max)
              dport = dport_min;
            break;
          case 2: // decreasing port numbers
            if ((dp = dport--) == dport_min)
              dport = dport_max;
            break;
          case 3: // pseudorandom port numbers
            std::uniform_int_distribution<int> uni_dis_dport(dport_min, dport_max); // uniform distribution in [sport_min, sport_max]
            dp = uni_dis_dport(gen_dport);
          }
          *udp_dport = htons(dp); // set the destination port 
          chksum += *udp_dport; // and add it to the UDP checksum
        }
      // And also save the current port numbers of the ps for later use of the same ps  
      if (direction == "forward")
        curr_sport_for_ps[psid] = sport; // save the current sport of the ps as a starting point for the later use if the same ps will be selected
      else
        curr_dport_for_ps[psid] = dport; // save the current dport of the ps as a starting point for the later use if the same ps will be selected
    }
    else
    { // background
      // change the value of the source and destination port numbers
        if (var_sport)
        {
          // sport is varying
          switch (var_sport)
          {
          case 1: // increasing port numbers
            if ((sp = bg_sport++) == bg_sport_max)
              bg_sport = bg_sport_min;
            break;
          case 2: // decreasing port numbers
            if ((sp = bg_sport--) == bg_sport_min)
              bg_sport = bg_sport_max;
            break;
          case 3: // pseudorandom port numbers
            std::uniform_int_distribution<int> uni_dis_sport(bg_sport_min, bg_sport_max); // uniform distribution in [sport_min, sport_max]
            sp = uni_dis_sport(gen_sport);
          }
          *udp_sport = htons(sp); // set the source port 
          chksum += *udp_sport; // and add it to the UDP checksum
        }
        if (var_dport)
        {
          // dport is varying
          switch (var_dport)
          {
          case 1: // increasing port numbers
            if ((dp = bg_dport++) == bg_dport_max)
              bg_dport = bg_dport_min;
            break;
          case 2: // decreasing port numbers
            if ((dp = bg_dport--) == bg_dport_min)
              bg_dport = bg_dport_max;
            break;
          case 3: // pseudorandom port numbers
            std::uniform_int_distribution<int> uni_dis_dport(bg_dport_min, bg_dport_max); // uniform distribution in [sport_min, sport_max]
            dp = uni_dis_dport(gen_dport);
          }
          *udp_dport = htons(dp); // set the destination port 
          chksum += *udp_dport; // and add it to the UDP checksum
        }
      
    }

//finalize the UDP checksum
    chksum = ((chksum & 0xffff0000) >> 16) + (chksum & 0xffff); // calculate 16-bit one's complement sum
    chksum = ((chksum & 0xffff0000) >> 16) + (chksum & 0xffff); // calculate 16-bit one's complement sum
    chksum = (~chksum) & 0xffff;                                // make one's complement
   
    if (direction == "reverse")
      {
        if (chksum == 0)                                        // checksum should not be 0 (0 means, no checksum is used)
          chksum = 0xffff;
      }
    *udp_chksum = (uint16_t)chksum; // set the UDP checksum in the frame

    
    // finally, send the frame
    while (rte_rdtsc() < start_tsc + sent_frames * hz / frame_rate)
      ; // Beware: an "empty" loop, as well as in the next line
    while (!rte_eth_tx_burst(eth_id, 0, &pkt_mbuf, 1))
      ; // send out the frame

    if (unlikely(sent_frames == send_next_latency_frame))
    {
      // the sent frame was a Latency Frame
      send_ts[latency_timestamp_no++] = rte_rdtsc(); // store its sending timestamp
      send_next_latency_frame = start_latency_frame + latency_timestamp_no * frames_to_send_during_latency_test / num_of_tagged; //prepare the index of the next latency frame
    }
    else
    {
      // the sent frame was a normal Test Frame
      i = (i + 1) % N;
    }
    current_CE = (current_CE + 1) % num_of_CEs;
  } // this is the end of the sending cycle

  // Now, we check the time
  elapsed_seconds = (double)(rte_rdtsc() - start_tsc) / hz;
  printf("Info: %s sender's sending took %3.10lf seconds.\n", direction, elapsed_seconds);
  if (elapsed_seconds > test_duration * TOLERANCE)
    rte_exit(EXIT_FAILURE, "%s sending exceeded the %3.10lf seconds limit, the test is invalid.\n", direction, test_duration * TOLERANCE);
  printf("%s frames sent: %lu\n", direction, sent_frames);
  return 0;
} // this is the end of the sendlatency function

// receives Test Frames for latency measurements including "num_of_tagged" number of Latency frames
// Offsets from the start of the Ethernet Frame:
// EtherType: 6+6=12
// IPv6 Next header: 14+6=20, UDP Data for IPv6: 14+40+8=62
// IPv4 Protolcol: 14+9=23, UDP Data for IPv4: 14+20+8=42
int receiveLatency(void *par)
{
  // collecting input parameters:
  class receiverParametersLatency *p = (class receiverParametersLatency *)par;
  uint64_t finish_receiving = p->finish_receiving;
  uint8_t eth_id = p->eth_id;
  const char *direction = p->direction;
  uint16_t num_of_tagged = p->num_of_tagged;
  uint64_t *receive_ts = p->receive_ts;

  // further local variables
  int frames, i;
  struct rte_mbuf *pkt_mbufs[MAX_PKT_BURST];                      // pointers for the mbufs of received frames
  uint16_t ipv4 = htons(0x0800);                                  // EtherType for IPv4 in Network Byte Order
  uint16_t ipv6 = htons(0x86DD);                                  // EtherType for IPv6 in Network Byte Order
  uint8_t identify[8] = {'I', 'D', 'E', 'N', 'T', 'I', 'F', 'Y'}; // Identificion of the Test Frames
  uint64_t *id = (uint64_t *)identify;
  uint8_t identify_latency[8] = {'I', 'd', 'e', 'n', 't', 'i', 'f', 'y'}; // Identificion of the Latency Frames
  uint64_t *id_lat = (uint64_t *)identify_latency;
  uint64_t received = 0; // number of received frames

  while (rte_rdtsc() < finish_receiving)
  {
    frames = rte_eth_rx_burst(eth_id, 0, pkt_mbufs, MAX_PKT_BURST);
    for (i = 0; i < frames; i++)
    {
      uint8_t *pkt = rte_pktmbuf_mtod(pkt_mbufs[i], uint8_t *); // Access the Test Frame in the message buffer
      // check EtherType at offset 12: IPv6, IPv4, or anything else
      if (*(uint16_t *)&pkt[12] == ipv6)
      { /* IPv6 */
        /* check if IPv6 Next Header is UDP, and the first 8 bytes of UDP data is 'IDENTIFY' */
        if (likely(pkt[20] == 17 && *(uint64_t *)&pkt[62] == *id))
          received++; // normal Test Frame
        else if (pkt[20] == 17 && *(uint64_t *)&pkt[62] == *id_lat) //UDP and 'Identify'
        {
          // Latency Frame
          uint64_t timestamp = rte_rdtsc(); // get a timestamp ASAP
          int latency_frame_id = *(uint16_t *)&pkt[70];
          if (latency_frame_id < 0 || latency_frame_id >= num_of_tagged)
            rte_exit(EXIT_FAILURE, "Error: Latency Frame with invalid frame ID was received!\n"); // to avoid segmentation fault
          receive_ts[latency_frame_id] = timestamp;
          received++; // Latency Frame is also counted as Test Frame
        }
      }
      else if (*(uint16_t *)&pkt[12] == ipv4)
      { /* IPv4 */
        /* check if IPv4 Next Header is UDP, and the first 8 bytes of UDP data is 'IDENTIFY' */
        if (likely(pkt[23] == 17 && *(uint64_t *)&pkt[42] == *id))
          received++; // normal Test Frame
        else if (pkt[23] == 17 && *(uint64_t *)&pkt[42] == *id_lat) //UDP and 'Identify'
        {
          // Latency Frame
          uint64_t timestamp = rte_rdtsc(); // get a timestamp ASAP
          int latency_frame_id = *(uint16_t *)&pkt[50];
          if (latency_frame_id < 0 || latency_frame_id >= num_of_tagged)
            rte_exit(EXIT_FAILURE, "Error: Latency Frame with invalid frame ID was received!\n"); // to avoid segmentation fault
          receive_ts[latency_frame_id] = timestamp;
          received++; // Latency Frame is also counted as Test Frame
        }
      }
      rte_pktmbuf_free(pkt_mbufs[i]);
    }
  }
  printf("%s frames received: %lu\n", direction, received);
  return received;
}

// performs latency measurement
void Latency::measure(uint16_t leftport, uint16_t rightport)
{
  uint64_t *left_send_ts, *right_send_ts, *left_receive_ts, *right_receive_ts; // pointers for timestamp arrays

  // set common parameters for senders
  senderCommonParametersLatency scp(ipv6_frame_size, ipv4_frame_size, frame_rate, test_duration, n, m, hz, start_tsc,
                                    num_of_CEs, num_of_port_sets, num_of_ports, &tester_left_ipv6, &tester_right_ipv4, &dmr_ipv6, &tester_right_ipv6,
                                    bg_sport_min, bg_sport_max, bg_dport_min, bg_dport_max,
                                    first_tagged_delay, num_of_tagged
                                    );

  if (forward)
  { // Left to right direction is active

    // create dynamic arrays for timestamps
    left_send_ts = new uint64_t[num_of_tagged];
    right_receive_ts = new uint64_t[num_of_tagged];
    if (!left_send_ts || !right_receive_ts)
      rte_exit(EXIT_FAILURE, "Error: Tester can't allocate memory for timestamps!\n");
    // fill with 0 (will be used to check, if frame with timestamp was received)
    memset(right_receive_ts, 0, num_of_tagged * sizeof(uint64_t));
    
    // set individual parameters for the left sender
    // initialize the parameter class instance
    senderParametersLatency spars(&scp, pkt_pool_left_sender, leftport, "forward", fwCE, (ether_addr *)dut_left_mac, (ether_addr *)tester_left_mac, 
                                  fwd_var_sport, fwd_var_dport, fwd_dport_min, fwd_dport_max, left_send_ts);

    // start left sender
    if (rte_eal_remote_launch(sendLatency, &spars, left_sender_cpu))
      std::cout << "Error: could not start Left Sender." << std::endl;

    // set parameters for the right receiver
    receiverParametersLatency rpars(finish_receiving, rightport, "forward", num_of_tagged, right_receive_ts);

    // start right receiver
    if (rte_eal_remote_launch(receiveLatency, &rpars, right_receiver_cpu))
      std::cout << "Error: could not start Right Receiver." << std::endl;
  }

  if (reverse)
  { // Right to Left direction is active

    // create dynamic arrays for timestamps
    right_send_ts = new uint64_t[num_of_tagged];
    left_receive_ts = new uint64_t[num_of_tagged];
    if (!right_send_ts || !left_receive_ts)
      rte_exit(EXIT_FAILURE, "Error: Tester can't allocate memory for timestamps!\n");
    // fill with 0 (will be used to chek, if frame with timestamp was received)
    memset(left_receive_ts, 0, num_of_tagged * sizeof(uint64_t));

    // set individual parameters for the right sender
    // initialize the parameter class instance
    senderParametersLatency spars(&scp, pkt_pool_right_sender, rightport, "reverse", rvCE, (ether_addr *)dut_right_mac, (ether_addr *)tester_right_mac,
                                  rev_var_sport, rev_var_dport, rev_sport_min, rev_sport_max, right_send_ts);

    // start right sender
    if (rte_eal_remote_launch(sendLatency, &spars, right_sender_cpu))
      std::cout << "Error: could not start Right Sender." << std::endl;

    // set parameters for the left receiver
    receiverParametersLatency rpars(finish_receiving, leftport, "reverse", num_of_tagged, left_receive_ts);

    // start left receiver
    if (rte_eal_remote_launch(receiveLatency, &rpars, left_receiver_cpu))
      std::cout << "Error: could not start Left Receiver." << std::endl;
  }

  std::cout << "Info: Testing started." << std::endl;

  // wait until active senders and receivers finish
  if (forward)
  {
    rte_eal_wait_lcore(left_sender_cpu);
    rte_eal_wait_lcore(right_receiver_cpu);
  }
  if (reverse)
  {
    rte_eal_wait_lcore(right_sender_cpu);
    rte_eal_wait_lcore(left_receiver_cpu);
  }

  // Process the timestamps
  int penalty = 1000 * (test_duration - first_tagged_delay) + stream_timeout; // latency to be reported for lost timestamps, expressed in milliseconds
  if (forward)
    evaluateLatency(num_of_tagged, left_send_ts, right_receive_ts, hz, penalty, "forward");
  if (reverse)
    evaluateLatency(num_of_tagged, right_send_ts, left_receive_ts, hz, penalty, "reverse");

  if (fwCE)
    rte_free(fwCE); // release the CEs data memory at the forward sender
  if (rvCE)
    rte_free(rvCE); // release the CEs data memory at the reverse sender
  if (fwUniqueEAComb) 
    rte_free(fwUniqueEAComb);	// release the memory of the pre-generated unique EA-bits combinations at the forward sender
  if (rvUniqueEAComb) 
    rte_free(rvUniqueEAComb);	// release the memory of the pre-generated unique EA-bits combinations at the reverse sender
  std::cout << "Info: Test finished." << std::endl;
}

// sets the values of the data fields
senderCommonParametersLatency::senderCommonParametersLatency(uint16_t ipv6_frame_size_, uint16_t ipv4_frame_size_, uint32_t frame_rate_, uint16_t test_duration_,
                                                             uint32_t n_, uint32_t m_, uint64_t hz_, uint64_t start_tsc_, uint32_t num_of_CEs_,
                                                             uint16_t num_of_port_sets_, uint16_t num_of_ports_,  struct in6_addr *tester_l_ipv6_, uint32_t *tester_r_ipv4_, 
                                                             struct in6_addr *dmr_ipv6_, struct in6_addr *tester_r_ipv6_,
                                                             uint16_t bg_sport_min_, uint16_t bg_sport_max_, uint16_t bg_dport_min_, uint16_t bg_dport_max_,
                                                             uint16_t first_tagged_delay_, uint16_t num_of_tagged_) : senderCommonParameters(ipv6_frame_size_, ipv4_frame_size_, frame_rate_, test_duration_, n_, m_, hz_, start_tsc_, num_of_CEs_,
                                                                                                                                             num_of_port_sets_, num_of_ports_, tester_l_ipv6_, tester_r_ipv4_, dmr_ipv6_, tester_r_ipv6_,
                                                                                                                                             bg_sport_min_, bg_sport_max_, bg_dport_min_, bg_dport_max_)
{
  first_tagged_delay = first_tagged_delay_;
  num_of_tagged = num_of_tagged_;
}

// sets the values of the data fields
senderParametersLatency::senderParametersLatency(class senderCommonParameters *cp_, rte_mempool *pkt_pool_, uint8_t eth_id_, const char *direction_,
                                                 CE_data *CE_array_, struct ether_addr *dst_mac_, struct ether_addr *src_mac_, unsigned var_sport_, unsigned var_dport_,
                                                 uint16_t preconfigured_port_min_, uint16_t preconfigured_port_max_, uint64_t *send_ts_) : senderParameters(cp_, pkt_pool_, eth_id_, direction_, CE_array_,
                                                                                                                                                            dst_mac_, src_mac_, var_sport_, var_dport_,
                                                                                                                                                            preconfigured_port_min_, preconfigured_port_max_)
{
  send_ts = send_ts_;
}

// sets the values of the data fields
receiverParametersLatency::receiverParametersLatency(uint64_t finish_receiving_, uint8_t eth_id_, const char *direction_,
                                                     uint16_t num_of_tagged_, uint64_t *receive_ts_) : receiverParameters(finish_receiving_, eth_id_, direction_)
{
  num_of_tagged = num_of_tagged_;
  receive_ts = receive_ts_;
}

void evaluateLatency(uint16_t num_of_tagged, uint64_t *send_ts, uint64_t *receive_ts, uint64_t hz, int penalty, const char *direction)
{
  double median_latency, worst_case_latency, *latency = new double[num_of_tagged];
  if (!latency)
    rte_exit(EXIT_FAILURE, "Error: Tester can't allocate memory for latency values!\n");
  for (int i = 0; i < num_of_tagged; i++)
    if (receive_ts[i])
      latency[i] = 1000.0 * (receive_ts[i] - send_ts[i]) / hz; // calculate and exchange into milliseconds
    else
      latency[i] = penalty; // penalty of the lost timestamp
  if (num_of_tagged < 2)
    median_latency = worst_case_latency = latency[0];
  else
  {
    std::sort(latency, latency + num_of_tagged);
    if (num_of_tagged % 2)
      median_latency = latency[num_of_tagged / 2]; // num_of_tagged is odd: median is the middle element
    else
      median_latency = (latency[num_of_tagged / 2 - 1] + latency[num_of_tagged / 2]) / 2; // num_of_tagged is even: median is the average of the two middle elements
    worst_case_latency = latency[int(ceil(0.999 * num_of_tagged)) - 1];                   // WCL is the 99.9th percentile
  }
  printf("%s TL: %lf\n", direction, median_latency);      // Typical Latency
  printf("%s WCL: %lf\n", direction, worst_case_latency); // Worst Case Latency
}
