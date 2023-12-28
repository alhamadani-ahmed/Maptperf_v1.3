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
#include "pdv.h"

// the understanding of this code requires the knowledge of throughput.c
// only a few functions are redefined or added here

// after reading the parameters for throughput measurement, further one parameter is read
int Pdv::readCmdLine(int argc, const char *argv[])
{
  if (Throughput::readCmdLine(argc - 1, argv) < 0)
    return -1;
  if (sscanf(argv[7], "%hu", &frame_timeout) != 1 || frame_timeout >= 1000 * test_duration + stream_timeout)
  {
    std::cerr << "Input Error: Frame timeout must be less than 1000*test_duration+stream_timeout, (0 means PDV measurement)." << std::endl;
    return -1;
  }
  return 0;
}

// creates a special IPv4 Test Frame for PDV measurement using several helper functions
struct rte_mbuf *mkPdvFrame4(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                             const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                             const uint32_t *src_ip, uint32_t *dst_ip, unsigned var_sport, unsigned var_dport)
{
  struct rte_mbuf *pkt_mbuf = rte_pktmbuf_alloc(pkt_pool); // message buffer for the PDV Frame
  if (!pkt_mbuf)
    rte_exit(EXIT_FAILURE, "Error: %s sender can't allocate a new mbuf for the PDV Frame! \n", direction);
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
  mkDataPdv(udp_data, data_length);
  udp_hd->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hd); // UDP checksum is calculated and set
  ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);               // IPv4 header checksum is set now
  return pkt_mbuf;
}

// creates a special IPv6 Test Frame for PDV measurement using several helper functions
struct rte_mbuf *mkPdvFrame6(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                             const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                             struct in6_addr *src_ip, struct in6_addr *dst_ip, unsigned var_sport, unsigned var_dport)
{
  struct rte_mbuf *pkt_mbuf = rte_pktmbuf_alloc(pkt_pool); // message buffer for the PDV Frame
  if (!pkt_mbuf)
    rte_exit(EXIT_FAILURE, "Error: %s sender can't allocate a new mbuf for the PDV Frame! \n", direction);
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
  mkDataPdv(udp_data, data_length);
  udp_hd->dgram_cksum = rte_ipv6_udptcp_cksum(ip_hdr, udp_hd); // UDP checksum is calculated and set
  return pkt_mbuf;
}

void mkDataPdv(uint8_t *data, uint16_t length)
{
  unsigned i;
  uint8_t identify[8] = {'I', 'D', 'E', 'N', 'T', 'I', 'F', 'Y'}; // Identification of the PDV Test Frames
  uint64_t *id = (uint64_t *)identify;
  *(uint64_t *)data = *id;
  data += 8;
  length -= 8;
  *(uint64_t *)data = 0; // place for the 64-bit serial number
  data += 8;
  length -= 8;
  for (i = 0; i < length; i++)
    data[i] = i % 256;
}

// sends Test Frames for PDV measurements
int sendPdv(void *par)
{
  // collecting input parameters:
  class senderParametersPdv *p = (class senderParametersPdv *)par;
  class senderCommonParameters *cp = (class senderCommonParameters *)p->cp;

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

  uint64_t **send_ts = p->send_ts;

  
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
    

  // prepare a NUMA local, cache line aligned array for send timestamps
  uint64_t *snd_ts = (uint64_t *)rte_malloc(0, 8 * frames_to_send, 128);
  if (!snd_ts)
    rte_exit(EXIT_FAILURE, "Error: Receiver can't allocate memory for timestamps!\n");
  *send_ts = snd_ts; // return the address of the array to the caller function

  // implementation of varying port numbers recommended by RFC 4814 https://tools.ietf.org/html/rfc4814#section-4.5
  // RFC 4814 requires pseudorandom port numbers, increasing and decreasing ones are our additional, non-stantard solutions
  // always the same foreground or background frame is sent, but it is updated regarding counter
  //source and/or destination IP addresses and port number(s), and UDP and IPv4 header checksum are updated
  // N size arrays are used to resolve the write after send problem
  
  //some worker variables
  int i;                                                       // cycle variable for the above mentioned purpose: takes {0..N-1} values
  int current_CE;                                              // index variable to the current simulated CE in the CE_array
  uint16_t psid;                                               // Temporary variable for the ID of the randomly selected port set for the simulated CE
  struct rte_mbuf *fg_pkt_mbuf[N], *bg_pkt_mbuf[N], *pkt_mbuf; // message buffers for fg. and bg. Test Frames
  uint8_t *pkt;                                                // working pointer to the current frame (in the message buffer)
  
  //IP workers
  uint32_t *fg_dst_ipv4[N];
  struct in6_addr *fg_src_ipv6[N];
  struct in6_addr *bg_src_ipv6[N], *bg_dst_ipv6[N];
  uint16_t *fg_ipv4_chksum[N]; 

  //UDP workers
  uint16_t *fg_udp_sport[N], *fg_udp_dport[N], *fg_udp_chksum[N], *bg_udp_sport[N], *bg_udp_dport[N], *bg_udp_chksum[N];
  uint16_t *udp_sport, *udp_dport, *udp_chksum; 

  uint16_t fg_udp_chksum_start, bg_udp_chksum_start, fg_ipv4_chksum_start; // starting values (uncomplemented checksums taken from the original frames created by mKTestFrame functions)
  uint32_t chksum = 0; // temporary variable for UDP checksum calculation
  uint32_t ip_chksum = 0; //temporary variable for IPv4 header checksum calculation
  uint16_t sport, dport, bg_sport, bg_dport; // values of source and destination port numbers -- to be preserved, when increase or decrease is done
  uint16_t sp, dp;                           // values of source and destination port numbers -- temporary values

  uint64_t *fg_counter[N], *bg_counter[N]; // pointers to the given fields
  uint64_t *counter;                       // working pointer to the counter in the currently manipulated frame

  // create buffers of template PDV Test Frames
  for (i = 0; i < N; i++)
  {
    // create foreground PDV Frame (IPv4 or IPv6)
    if (direction == "reverse")
    {

      fg_pkt_mbuf[i] = mkPdvFrame4(ipv4_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv4, dst_ipv4, var_sport, var_dport);
      pkt = rte_pktmbuf_mtod(fg_pkt_mbuf[i], uint8_t *); // Access the Test Frame in the message buffer
      // the source ipv4 address will not be manipulated as it will permenantly be the tester-right-ipv4 (extracted from the dmr-ipv6 as done above)
      fg_ipv4_chksum[i] = (uint16_t *)(pkt + 24);
      fg_dst_ipv4[i] = (uint32_t *)(pkt + 30); // The destination ipv4 should be manipulated in the sending loop as it will be the BMR-ipv4-prefix + suffix (i.e. changine each time) in the reverse direction
      // The source address will not be manipulated as it will permentantly be the IP address of the right interface of the Tester (as done in the initilization above)
      fg_udp_sport[i] = (uint16_t *)(pkt + 34);
      fg_udp_dport[i] = (uint16_t *)(pkt + 36);
      fg_udp_chksum[i] = (uint16_t *)(pkt + 40);
      fg_counter[i] = (uint64_t *)(pkt + 50);
    }
    else
    { //"forward"
      fg_pkt_mbuf[i] = mkPdvFrame6(ipv6_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv6, dst_ipv6, var_sport, var_dport);
      pkt = rte_pktmbuf_mtod(fg_pkt_mbuf[i], uint8_t *); // Access the Test Frame in the message buffer
      fg_src_ipv6[i] = (struct in6_addr *)(pkt + 22);    // The source address should be manipulated as it will be the MAP address (i.e. changing each time) in the forward direction
      // The destination address will not be manipulated as it will permenantly be the DMR IPv6 address (as done in the initilization above)
      fg_udp_sport[i] = (uint16_t *)(pkt + 54);
      fg_udp_dport[i] = (uint16_t *)(pkt + 56);
      fg_udp_chksum[i] = (uint16_t *)(pkt + 60);
      fg_counter[i] = (uint64_t *)(pkt + 70);
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
    bg_counter[i] = (uint64_t *)(pkt + 70);
  }
  //save the uncomplemented UDP checksum value (same for all values of [i]). So, [0] is enough
  fg_udp_chksum_start = ~*fg_udp_chksum[0]; // for the foreground frames 
  bg_udp_chksum_start = ~*bg_udp_chksum[0]; // same but for the background frames
  
  // save the uncomplementd IPv4 header checksum (same for all values of [i]). So, [0] is enough
  if (direction == "reverse") // in case of foreground IPv4 only
      fg_ipv4_chksum_start = ~*fg_ipv4_chksum[0]; 

  // arrays to store the minimum and maximum possible souce and destination port numbers in each port set.
  uint16_t sport_min_for_ps[num_of_port_sets], sport_max_for_ps[num_of_port_sets], dport_min_for_ps[num_of_port_sets], dport_max_for_ps[num_of_port_sets];

  // arrays of indices to know the current source and destination port numbers for each port set, to be used in case of incrementing or decrementing
  uint16_t curr_sport_for_ps[num_of_port_sets];  // used to restore the last used sport in the port set to set the next sport to.
  uint16_t curr_dport_for_ps[num_of_port_sets];  // used to restore the last used dport in the port set to set the next dport to.
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


  i = 0; // increase maunally after each sending
  current_CE = 0; // increase maunally after each sending

  // prepare random number infrastructure
  thread_local std::random_device rd_sport;           // Will be used to obtain a seed for the random number engines
  thread_local std::mt19937_64 gen_sport(rd_sport()); // Standard 64-bit mersenne_twister_engine seeded with rd()
  thread_local std::random_device rd_dport;           // Will be used to obtain a seed for the random number engines
  thread_local std::mt19937_64 gen_dport(rd_dport()); // Standard 64-bit mersenne_twister_engine seeded with rd()

  // naive sender version: it is simple and fast
  for (sent_frames = 0; sent_frames < frames_to_send; sent_frames++)
  { // Main cycle for the number of frames to send
    // set the temporary variables (including several pointers) to handle the right pre-generated Test Frame

    if (sent_frames % n < m)
    {
      // foreground frame is to be sent

      psid = CE_array[current_CE].psid;
      chksum = fg_udp_chksum_start; // restore the uncomplemented UDP checksum to add the values of the varying fields
      udp_sport = fg_udp_sport[i];
      udp_dport = fg_udp_dport[i];
      udp_chksum = fg_udp_chksum[i];
      counter = fg_counter[i];
      pkt_mbuf = fg_pkt_mbuf[i];

      if (direction == "forward")
      {

        *fg_src_ipv6[i] = CE_array[current_CE].map_addr; // set it with the map address
        chksum += CE_array[current_CE].map_addr_chksum; // and add it to the UDP checksum

        // the sport_min and sport_max will be set according to the port range values of the selected port set and the sport will retrieve its last value within this range
        // the dport_min and dport_max will remain on thier default values within the wide range. The dport will be changed based on its value from the last cycle.
        sport_min = sport_min_for_ps[psid];
        sport_max = sport_max_for_ps[psid];
        if (var_sport == 1 || var_sport == 2)
          sport = curr_sport_for_ps[psid]; // restore the last used sport in the ps to start over from it (useful when increment or decrement; useless when random)
      }

      if (direction == "reverse")
      {
        ip_chksum = fg_ipv4_chksum_start;

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
   // time to change the value of the source and destination port numbers
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
    if (direction == "forward")
        curr_sport_for_ps[psid] = sport; // save the current sport of the ps as a starting point for the later use if the same ps will be selected
      else
        curr_dport_for_ps[psid] = dport; // save the current dport of the ps as a starting point for the later use if the same ps will be selected
    }
    else
    {
      // background frame is to be sent
      // from here, we need to handle the background frame identified by the temporary variables

      chksum = bg_udp_chksum_start; // restore the uncomplemented UDP checksum to add the values of the varying fields
      udp_sport = bg_udp_sport[i];
      udp_dport = bg_udp_dport[i];
      udp_chksum = bg_udp_chksum[i];
      counter = bg_counter[i];
      pkt_mbuf = bg_pkt_mbuf[i];

      // time to change the value of the source and destination port numbers
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
    
   
    *counter = sent_frames;                   // set the counter in the frame
    chksum += rte_raw_cksum(&sent_frames, 8); // add the checksum of the counter to the accumulated checksum value

    chksum = ((chksum & 0xffff0000) >> 16) + (chksum & 0xffff); // calculate 16-bit one's complement sum
    chksum = ((chksum & 0xffff0000) >> 16) + (chksum & 0xffff); // Twice is enough
    chksum = (~chksum) & 0xffff;                                // make one's complement
    
    if (direction == "reverse")
    {
      if (chksum == 0)                                            // checksum should not be 0 (0 means, no checksum is used)
        chksum = 0xffff;
    }
    *udp_chksum = (uint16_t)chksum; // set the UDP checksum in the frame

    // finally, send the frame
    while (rte_rdtsc() < start_tsc + sent_frames * hz / frame_rate)
      ; // Beware: an "empty" loop, as well as in the next line
    while (!rte_eth_tx_burst(eth_id, 0, &pkt_mbuf, 1))
      ; // send out the frame

    snd_ts[sent_frames] = rte_rdtsc(); // store timestamp
    current_CE = (current_CE + 1) % num_of_CEs;
    i = (i + 1) % N;
  } // this is the end of the sending cycle

  // Now, we check the time
  elapsed_seconds = (double)(rte_rdtsc() - start_tsc) / hz;
  printf("Info: %s sender's sending took %3.10lf seconds.\n", direction, elapsed_seconds);
  if (elapsed_seconds > test_duration * TOLERANCE)
    rte_exit(EXIT_FAILURE, "%s sending exceeded the %3.10lf seconds limit, the test is invalid.\n", direction, test_duration * TOLERANCE);
  printf("%s frames sent: %lu\n", direction, sent_frames);
  return 0;
}

// Offsets from the start of the Ethernet Frame:
// EtherType: 6+6=12
// IPv6 Next header: 14+6=20, UDP Data for IPv6: 14+40+8=62
// IPv4 Protolcol: 14+9=23, UDP Data for IPv4: 14+20+8=42
int receivePdv(void *par)
{
  // collecting input parameters:
  class receiverParametersPdv *p = (class receiverParametersPdv *)par;
  uint64_t finish_receiving = p->finish_receiving;
  uint8_t eth_id = p->eth_id;
  const char *direction = p->direction;
  uint64_t num_frames = p->num_frames;
  uint16_t frame_timeout = p->frame_timeout;
  uint64_t **receive_ts = p->receive_ts;

  // further local variables
  int frames, i;
  uint64_t timestamp, counter;
  struct rte_mbuf *pkt_mbufs[MAX_PKT_BURST];                      // pointers for the mbufs of received frames
  uint16_t ipv4 = htons(0x0800);                                  // EtherType for IPv4 in Network Byte Order
  uint16_t ipv6 = htons(0x86DD);                                  // EtherType for IPv6 in Network Byte Order
  uint8_t identify[8] = {'I', 'D', 'E', 'N', 'T', 'I', 'F', 'Y'}; // Identificion of the Test Frames
  uint64_t *id = (uint64_t *)identify;
  uint64_t received = 0; // number of received frames

  // prepare a NUMA local, cache line aligned array for reveive timestamps, and fill it with all 0-s
  uint64_t *rec_ts = (uint64_t *)rte_zmalloc(0, 8 * num_frames, 128);
  if (!rec_ts)
    rte_exit(EXIT_FAILURE, "Error: Receiver can't allocate memory for timestamps!\n");
  *receive_ts = rec_ts; // return the address of the array to the caller function

  while (rte_rdtsc() < finish_receiving)
  {
    frames = rte_eth_rx_burst(eth_id, 0, pkt_mbufs, MAX_PKT_BURST);
    for (i = 0; i < frames; i++)
    {
      uint8_t *pkt = rte_pktmbuf_mtod(pkt_mbufs[i], uint8_t *); // Access the PDV Frame in the message buffer
      // check EtherType at offset 12: IPv6, IPv4, or anything else
      if (*(uint16_t *)&pkt[12] == ipv6)
      { /* IPv6 */
        /* check if IPv6 Next Header is UDP, and the first 8 bytes of UDP data is 'IDENTIFY' */
        if (likely(pkt[20] == 17 && *(uint64_t *)&pkt[62] == *id))
        {
          // PDV frame
          timestamp = rte_rdtsc(); // get a timestamp ASAP
          counter = *(uint64_t *)&pkt[70];
          if (unlikely(counter >= num_frames))
            rte_exit(EXIT_FAILURE, "Error: PDV Frame with invalid frame ID was received!\n"); // to avoid segmentation fault
          rec_ts[counter] = timestamp;
          received++; // also count it
        }
      }
      else if (*(uint16_t *)&pkt[12] == ipv4)
      { /* IPv4 */
        if (likely(pkt[23] == 17 && *(uint64_t *)&pkt[42] == *id))
        {
          // Latency Frame
          timestamp = rte_rdtsc(); // get a timestamp ASAP
          counter = *(uint64_t *)&pkt[50];
          if (unlikely(counter >= num_frames))
            rte_exit(EXIT_FAILURE, "Error: PDV Frame with invalid frame ID was received!\n"); // to avoid segmentation fault
          rec_ts[counter] = timestamp;
          received++; // also count it
        }
      }
      rte_pktmbuf_free(pkt_mbufs[i]);
    }
  }
  if (frame_timeout == 0)
    printf("%s frames received: %lu\n", direction, received); //  printed if normal PDV, but not printed if special throughput measurement is done
  return received;
}

// performs PDV measurement
void Pdv::measure(uint16_t leftport, uint16_t rightport)
{
  uint64_t *left_send_ts, *right_send_ts, *left_receive_ts, *right_receive_ts; // pointers for timestamp arrays

  // set common parameters for senders
  senderCommonParameters scp(ipv6_frame_size, ipv4_frame_size, frame_rate, test_duration, n, m, hz, start_tsc,
                             num_of_CEs, num_of_port_sets, num_of_ports,  &tester_left_ipv6, &tester_right_ipv4, &dmr_ipv6, &tester_right_ipv6,
                             bg_sport_min, bg_sport_max, bg_dport_min, bg_dport_max
                             );

  if (forward)
  { // Left to right direction is active

    // set individual parameters for the left sender
    // initialize the parameter class instance
    senderParametersPdv spars(&scp, pkt_pool_left_sender, leftport, "forward", fwCE, (ether_addr *)dut_left_mac, (ether_addr *)tester_left_mac, fwd_var_sport, fwd_var_dport, fwd_dport_min, fwd_dport_max, &left_send_ts);

    // start left sender
    if (rte_eal_remote_launch(sendPdv, &spars, left_sender_cpu))
      std::cout << "Error: could not start Left Sender." << std::endl;

    // set parameters for the right receiver
    receiverParametersPdv rpars(finish_receiving, rightport, "forward", test_duration * frame_rate, frame_timeout, &right_receive_ts);

    // start right receiver
    if (rte_eal_remote_launch(receivePdv, &rpars, right_receiver_cpu))
      std::cout << "Error: could not start Right Receiver." << std::endl;
  }

  if (reverse)
  { // Right to Left direction is active
    
    // set individual parameters for the right sender
    // initialize the parameter class instance
    senderParametersPdv spars(&scp, pkt_pool_right_sender, rightport, "reverse", rvCE, (ether_addr *)dut_right_mac, (ether_addr *)tester_right_mac,
                              rev_var_sport, rev_var_dport, rev_sport_min, rev_sport_max, &right_send_ts);

    // start right sender
    if (rte_eal_remote_launch(sendPdv, &spars, right_sender_cpu))
      std::cout << "Error: could not start Right Sender." << std::endl;

    // set parameters for the left receiver
    receiverParametersPdv rpars(finish_receiving, leftport, "reverse", test_duration * frame_rate, frame_timeout, &left_receive_ts);

    // start left receiver
    if (rte_eal_remote_launch(receivePdv, &rpars, left_receiver_cpu))
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
  int penalty = 1000 * test_duration + stream_timeout; // latency to be reported for lost timestamps, expressed in milliseconds

  if (forward)
    evaluatePdv(test_duration * frame_rate, left_send_ts, right_receive_ts, hz, frame_timeout, penalty, "forward");
  if (reverse)
    evaluatePdv(test_duration * frame_rate, right_send_ts, left_receive_ts, hz, frame_timeout, penalty, "reverse");

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
senderParametersPdv::senderParametersPdv(class senderCommonParameters *cp_, rte_mempool *pkt_pool_, uint8_t eth_id_, const char *direction_,
                                         CE_data *CE_array_, struct ether_addr *dst_mac_, struct ether_addr *src_mac_, unsigned var_sport_, unsigned var_dport_,
                                         uint16_t preconfigured_port_min_, uint16_t preconfigured_port_max_,
                                         uint64_t **send_ts_) : senderParameters(cp_, pkt_pool_, eth_id_, direction_,
                                                                                 CE_array_, dst_mac_, src_mac_, var_sport_, var_dport_,
                                                                                 preconfigured_port_min_, preconfigured_port_max_)
{
  send_ts = send_ts_;
}

// sets the values of the data fields
receiverParametersPdv::receiverParametersPdv(uint64_t finish_receiving_, uint8_t eth_id_, const char *direction_,
                                             uint64_t num_frames_, uint16_t frame_timeout_, uint64_t **receive_ts_) : receiverParameters(finish_receiving_, eth_id_, direction_)
{
  num_frames = num_frames_;
  frame_timeout = frame_timeout_;
  receive_ts = receive_ts_;
}

void evaluatePdv(uint64_t num_of_frames, uint64_t *send_ts, uint64_t *receive_ts, uint64_t hz, uint16_t frame_timeout, int penalty, const char *direction)
{
  int64_t frame_to = frame_timeout * hz / 1000;  // exchange frame timeout from ms to TSC
  int64_t penalty_tsc = penalty * hz / 1000;     // exchange penaly from ms to TSC
  int64_t PDV, Dmin, D99_9th_perc, Dmax;         // signed variable are used to prevent [-Wsign-compare] warning :-)
  uint64_t i;                                    // cycle variable
  int64_t *latency = new int64_t[num_of_frames]; // negative delay may occur, see the paper for details
  uint64_t num_corrected = 0;                    // number of negative delay values corrected to 0
  uint64_t frames_lost = 0;                      // the number of physically lost frames

  if (!latency)
    rte_exit(EXIT_FAILURE, "Error: Tester can't allocate memory for latency values!\n");
  for (i = 0; i < num_of_frames; i++)
  {
    if (receive_ts[i])
    {
      latency[i] = receive_ts[i] - send_ts[i]; // packet delay in TSC
      if (unlikely(latency[i] < 0))
      {
        latency[i] = 0; // correct negative delay to 0
        num_corrected++;
      }
    }
    else
    {
      frames_lost++;            // frame physically lost
      latency[i] = penalty_tsc; // penalty of the lost timestamp
    }
  }
  if (num_corrected)
    printf("Debug: %s number of negative delay values corrected to 0: %lu\n", direction, num_corrected);
  if (frame_timeout)
  {
    // count the frames arrived in time
    uint64_t frames_received = 0;
    for (i = 0; i < num_of_frames; i++)
      if (latency[i] <= frame_to)
        frames_received++;
    printf("%s frames received: %lu\n", direction, frames_received);
    printf("Info: %s frames completely missing: %lu\n", direction, frames_lost);
  }
  else
  {
    // calculate PDV
    // first, find Dmin
    Dmin = Dmax = latency[0];
    for (i = 1; i < num_of_frames; i++)
    {
      if (latency[i] < Dmin)
        Dmin = latency[i];
      if (latency[i] > Dmax)
        Dmax = latency[i];
      if (latency[i] > penalty_tsc)
        printf("Debug: BUG: i=%lu, send_ts[i]=%lu, receive_ts[i]=%lu, latency[i]=%lu\n", i, send_ts[i], receive_ts[i], latency[i]);
    }
    // then D99_9th_perc
    std::sort(latency, latency + num_of_frames);
    D99_9th_perc = latency[int(ceil(0.999 * num_of_frames)) - 1];
    PDV = D99_9th_perc - Dmin;
    printf("Info: %s D99_9th_perc: %lf\n", direction, 1000.0 * D99_9th_perc / hz);
    printf("Info: %s Dmin: %lf\n", direction, 1000.0 * Dmin / hz);
    printf("Info: %s Dmax: %lf\n", direction, 1000.0 * Dmax / hz);
    printf("%s PDV: %lf\n", direction, 1000.0 * PDV / hz);
  }
}
