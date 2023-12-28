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

#ifndef THROUGHPUT_H_INCLUDED
#define THROUGHPUT_H_INCLUDED


// used for generating EA-bits (ipv4 suffix and psid) combinations using random permutation
struct EAbits48{
  uint32_t ip4_suffix;	// The Ipv4 suffix
  uint16_t psid;	// The port set id
};

// a union facilitating the access of the EA-bits as a 48-bit number
/*union EAbits48 {
  fieldPair field;
  fieldPair EA_data;
};*/

// the data of a simulated CE (i.e., its ipv6 map address+its checksum, assigned ipv4 address (BMR prefix+ randomly generated suffix)+its checksum, and randomly generated psid)
// In the forward direction: the map address will be part of the ipv6 generated packets before send().
// In the reverse direction: the ipv4 address will be part of the ipv4 generated packets before send().
// The psid will be part of the map address and be used for identifying the port range that could be deployed
// by this simulated CE. The ipv4 suffix of the map address and psid will both uniquely identify this simulated CE.

struct CE_data
{
public:
  uint32_t ipv4_addr;
  uint16_t ipv4_addr_chksum;
  struct in6_addr map_addr;
  uint32_t map_addr_chksum;
  uint16_t psid; // The ID of the randomly selected port set for the simulated CE
};

// the main class for maptperf
// data members are used for storing parameters
// member functions are used for the most important functions
// but send() and receive() are NOT member functions, due to limitations of rte_eal_remote_launch()
class Throughput
{
public:
  // parameters from the configuration file
  struct in6_addr tester_left_ipv6;  // Tester's left interface IPv6 address (unused for now as we will use the MAP address instead)
  uint32_t tester_right_ipv4;        // Tester's right interface IPv4 address
  struct in6_addr tester_right_ipv6; // Tester's right interface IPv6 address (used for sending background traffic)

  uint8_t tester_left_mac[6];  // Tester's left interface MAC address
  uint8_t tester_right_mac[6]; // Tester's right interface MAC address
  uint8_t dut_left_mac[6];     // DUT's left interface MAC address
  uint8_t dut_right_mac[6];    // DUT's right interface MAC address

  // encoding: 1: increase, 2: decrease, 3: pseudorandom
  unsigned fwd_var_sport; // control value for variable source port numbers in the forward direction
  unsigned fwd_var_dport; // control value for variable destination port numbers in the forward direction
  unsigned rev_var_sport; // control value for variable source port numbers in the reverse direction
  unsigned rev_var_dport; // control value for variable destination port numbers in the reverse direction

  uint16_t fwd_dport_min; // minumum value for foreground's destination port in the forward direction
  uint16_t fwd_dport_max; // maximum value for foreground's destination port in the forward direction
  uint16_t rev_sport_min; // minumum value for foreground's source port in the reverse direction
  uint16_t rev_sport_max; // maximum value for foreground's source port in the reverse direction

  uint16_t bg_dport_min; // minumum value for background's destination port in the forward direction
  uint16_t bg_dport_max; // maximum value for background's destination port in the forward direction
  uint16_t bg_sport_min; // minumum value for background's source port in the reverse direction
  uint16_t bg_sport_max; // maximum value for background's source port in the reverse direction

  uint32_t num_of_CEs;             // Number of simulated CEs
  struct in6_addr bmr_ipv6_prefix; // The BMR’s Rule IPv6 Prefix of the MAP address
  uint8_t bmr_ipv6_prefix_length;  // The BMR's Rule IPv6 Prefix length
  uint32_t bmr_ipv4_prefix;        // The BMR’s public IPv4 prefix that is reserved for CEs in the MAP domain
  uint8_t bmr_ipv4_prefix_length;  // The BMR's IPv4 prefix length
  uint8_t bmr_EA_length;           // The number of EA bits
  struct in6_addr dmr_ipv6_prefix; // The IPv6 prefix that will be added by DMR to the public IPv4 address
  uint8_t dmr_ipv6_prefix_length;  // The DMR's IPv6 prefix length : should be between 64 and 96 bits according to RFC 7599

  int left_sender_cpu;    // lcore for left side Sender
  int right_receiver_cpu; // lcore for right side Receiver
  int right_sender_cpu;   // lcore for right side Sender
  int left_receiver_cpu;  // lcore for left side Receiver

  uint8_t memory_channels; // Number of memory channnels (for the EAL init.)
  int forward, reverse;    // directions are active if set
  int promisc;             // promiscuous mode is active if set

  // positional parameters from command line
  uint16_t ipv6_frame_size; // size of the frames carrying IPv6 datagrams (including the 4 bytes of the FCS at the end)
  uint16_t ipv4_frame_size; // redundant parameter, automatically set as ipv6_frame_size-20
  uint32_t frame_rate;      // number of frames per second
  uint16_t test_duration;   // test duration (in seconds, 1-3600)
  uint16_t stream_timeout;  // Stream timeout (in milliseconds, 0-60000)
  uint32_t n, m;            // modulo and threshold for controlling background traffic proportion

  // further data members, set by init()
  rte_mempool *pkt_pool_left_sender, *pkt_pool_right_receiver; // packet pools for the forward direction testing
  rte_mempool *pkt_pool_right_sender, *pkt_pool_left_receiver; // packet pools for the reverse direction testing
  uint64_t hz;                                                 // number of clock cycles per second
  uint64_t start_tsc;                                          // sending of the test frames will begin at this time
  uint64_t finish_receiving;                                   // receiving of the test frames will end at this time
  uint64_t frames_to_send;                                     // number of frames to send

  EAbits48 *fwUniqueEAComb;       // array of pre-generated unique EA-bits (ipv4 suffix and psid) combinations, to be used by the forward sender
  EAbits48 *rvUniqueEAComb;       // same as above, but for the reverse sender
  CE_data *fwCE;                  // a pointer to the currently simulated CE's data in the forward direction.
  CE_data *rvCE;                  // a pointer to the currently simulated CE's data in the reverse direction.
  uint8_t bmr_ipv4_suffix_length; // The BMR's IPv4 suffix length
  uint8_t psid_length;            // The number of BMR's PSID bits
  uint16_t num_of_port_sets;      // The number of port sets that can be obtained according to the psid_length
  uint16_t num_of_ports;          // The number of ports in each port set
  //uint32_t num_of_suffixes;       // The total number of ipv4 suffixes that can be obtained according to bmr_ipv4_suffix_length
  //uint32_t bmr_ipv4_suffix;       // The randomly selected ipv4 suffix for the simulated CE
  //uint8_t bmr_ipv6_prefix_bytes;  // number of bytes allocated to the bmr_ipv6_prefix in the map address
  //uint8_t bmr_ipv6_prefix_bits;   // number of bits in the last byte fragment needed to complete the bmr_ipv6_prefix in the map address
  struct in6_addr dmr_ipv6;       // The DMR ipv6 address (It will be the destination address in the forward direction. 
                                  // The IPv4 source address in the reverse direction will be derived from the dmr_ipv6)

  // helper functions (see their description at their definition)
  int findKey(const char *line, const char *key);
  int readConfigFile(const char *filename);
  int readCmdLine(int argc, const char *argv[]);
  int init(const char *argv0, uint16_t leftport, uint16_t rightport);
  virtual int senderPoolSize();
  void numaCheck(uint16_t port, const char *port_side, int cpu, const char *cpu_name);
  //void buildMapArray();

  // perform throughput measurement
  void measure(uint16_t leftport, uint16_t rightport);

  Throughput();
};

// functions to create Test Frames (and their parts)
struct rte_mbuf *mkTestFrame4(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                              const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                              const uint32_t *src_ip, uint32_t *dst_ip, unsigned var_sport, unsigned var_dport);
void mkEthHeader(struct ether_hdr *eth, const struct ether_addr *dst_mac, const struct ether_addr *src_mac, const uint16_t ether_type);
void mkIpv4Header(struct ipv4_hdr *ip, uint16_t length, const uint32_t *src_ip, uint32_t *dst_ip);
void mkUdpHeader(struct udp_hdr *udp, uint16_t length, unsigned var_sport, unsigned var_dport);
void mkData(uint8_t *data, uint16_t length);
struct rte_mbuf *mkTestFrame6(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                              const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                              struct in6_addr *src_ip, struct in6_addr *dst_ip, unsigned var_sport, unsigned var_dport);
void mkIpv6Header(struct ipv6_hdr *ip, uint16_t length, struct in6_addr *src_ip, struct in6_addr *dst_ip);

// report the current TSC of the exeucting core
int report_tsc(void *par);

// check if the TSC of the given core is synchronized with the TSC of the main core
void check_tsc(int cpu, const char *cpu_name);

// send test frame
int send(void *par);

// receive and count test frames
int receive(void *par);

// concatenate two uint64_t values to form an IPv6 address
// It is used to concatenate the end user IPv6 prefix and the interface ID to form the MAP address
struct in6_addr concatenate(uint64_t in1, uint64_t in2);

// to store identical parameters for both senders
class senderCommonParameters
{
public:
  uint16_t ipv6_frame_size; 
  uint16_t ipv4_frame_size; 
  uint32_t frame_rate;      
  uint16_t test_duration;   
  uint32_t n, m;            
  uint64_t hz;              
  uint64_t start_tsc;       
  uint64_t frames_to_send;  
  uint32_t num_of_CEs;
  uint16_t num_of_port_sets;
  uint16_t num_of_ports;
  struct in6_addr *tester_l_ipv6;
  uint32_t *tester_r_ipv4;
  struct in6_addr *dmr_ipv6;
  struct in6_addr *tester_r_ipv6; // The ipv6 address that will be used for background traffic (This will be the dest. addr. in case of forward and the src. addr. in case of reverse)
  uint16_t bg_dport_min; 
  uint16_t bg_dport_max; 
  uint16_t bg_sport_min; 
  uint16_t bg_sport_max;

  senderCommonParameters(uint16_t ipv6_frame_size_, uint16_t ipv4_frame_size_, uint32_t frame_rate_, uint16_t test_duration_,
                         uint32_t n_, uint32_t m_, uint64_t hz_, uint64_t start_tsc_, uint32_t num_of_CEs_, uint16_t num_of_port_sets_,
                         uint16_t num_of_ports_, struct in6_addr *tester_l_ipv6_, uint32_t *tester_r_ipv4_, struct in6_addr *dmr_ipv6_, 
                         struct in6_addr *tester_r_ipv6_, uint16_t bg_sport_min_, uint16_t bg_sport_max_, uint16_t bg_dport_min_, uint16_t bg_dport_max_
                         );
};

// to store the distinct parameters of each sender + a pointer to the common ones
class senderParameters
{
public:
  class senderCommonParameters *cp; // a pointer to the common parameters
  rte_mempool *pkt_pool; // sender's packet pool
  uint8_t eth_id; // ethernet ID
  const char *direction; // test direction (forward or reverse)
  CE_data *CE_array;
  struct ether_addr *dst_mac, *src_mac; // destination and source mac addresses
  unsigned var_sport, var_dport; // how source and destination port numbers vary? 1:increase, 2:decrease, or 3:pseudorandomly change
  uint16_t preconfigured_port_min, preconfigured_port_max; // The preconfigured range of ports (i.e., destination in case of forward and source in case of reverse)
  
  senderParameters(class senderCommonParameters *cp_, rte_mempool *pkt_pool_, uint8_t eth_id_, const char *direction_,
                   CE_data *CE_array_, struct ether_addr *dst_mac_, struct ether_addr *src_mac_, unsigned var_sport_, unsigned var_dport_,
                   uint16_t preconfigured_port_min_, uint16_t preconfigured_port_max_
                   );
};

// to store parameters for each receiver
class receiverParameters
{
public:
  uint64_t finish_receiving; // this one is common, but it was not worth dealing with it.
  uint8_t eth_id;
  const char *direction;
  receiverParameters(uint64_t finish_receiving_, uint8_t eth_id_, const char *direction_);
};


void randomPermutation48(EAbits48 *array, uint8_t ip4_suffix_length, uint8_t psid_length);

int randomPermutationGenerator48(void *par);

// to store the parameters for randomPermutationGenerator48
class randomPermutationGeneratorParameters48 {
  public:
  EAbits48 **addr_of_arraypointer;	// pointer to the place, where the pointer is stored 
  uint8_t ip4_suffix_length;
  uint8_t psid_length;
  uint64_t hz;			// just to be able to display the execution time
  const char *direction; // test direction (forward or reverse). To be used for showing for which sender this EA combinations array belongs.

};

int buildCEArray(void *par);
//
class CEArrayBuilderParameters{
  public:
  CE_data **addr_of_arraypointer;	// pointer to the place, where the pointer is stored
  EAbits48 *UniqueEAComb;       // array of pre-generated unique EA-bits (ipv4 suffix and psid) combinations, to be used by the relative sender
  uint8_t bmr_ipv4_suffix_length; // The BMR's IPv4 suffix length
  uint8_t psid_length;            // The number of BMR's PSID bits
  uint32_t num_of_CEs;             // Number of simulated CEs
  struct in6_addr bmr_ipv6_prefix; // The BMR’s Rule IPv6 Prefix of the MAP address
  uint8_t bmr_ipv6_prefix_length;  // The BMR's Rule IPv6 Prefix length
  uint32_t bmr_ipv4_prefix;        // The BMR’s public IPv4 prefix that is reserved for CEs in the MAP domain
  uint64_t hz;			// just to be able to display the execution time
  const char *direction; // test direction (forward or reverse). To be used for showing for which sender this CE array belongs.
};


#endif
