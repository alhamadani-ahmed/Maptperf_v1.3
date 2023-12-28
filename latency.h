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

#ifndef LATENCY_H_INCLUDED
#define LATENCY_H_INCLUDED

// the main class for latency measurements, adds some features to class Throughput
class Latency : public Throughput
{
public:
  uint16_t first_tagged_delay; // time period while frames are sent, but no timestamps are used; then timestaps are used in the "test_duration-first_tagged_delay" length interval
  uint16_t num_of_tagged;      // number of tagged frames, 1-50000 is accepted, RFC 8219 requires at least 500, RFC 2544 requires 1

  Latency() : Throughput(){};                    // default constructor
  int readCmdLine(int argc, const char *argv[]); // reads further two arguments
  virtual int senderPoolSize();                  // adds num_of_tagged, too

  // perform latency measurement
  void measure(uint16_t leftport, uint16_t rightport);
};

// functions to create Latency Frames (and their parts)
struct rte_mbuf *mkLatencyFrame4(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                                 const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                                 const uint32_t *src_ip, const uint32_t *dst_ip, unsigned var_sport, unsigned var_dport, uint16_t id);
void mkDataLatency(uint8_t *data, uint16_t length, uint16_t latency_frame_id);
struct rte_mbuf *mkLatencyFrame6(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                                 const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                                 const struct in6_addr *src_ip, const struct in6_addr *dst_ip, unsigned var_sport, unsigned var_dport, uint16_t id);

class senderCommonParametersLatency : public senderCommonParameters
{
public:
  uint16_t first_tagged_delay; //The amount of delay before sending the first tagged frame
  uint16_t num_of_tagged; // The number of tagged frames

  senderCommonParametersLatency(uint16_t ipv6_frame_size_, uint16_t ipv4_frame_size_, uint32_t frame_rate_, uint16_t test_duration_,
                                uint32_t n_, uint32_t m_, uint64_t hz_, uint64_t start_tsc_, uint32_t num_of_CEs_, uint16_t num_of_port_sets_,
                                uint16_t num_of_ports_, struct in6_addr *tester_l_ipv6_, uint32_t *tester_r_ipv4_, struct in6_addr *dmr_ipv6_,
                                struct in6_addr *tester_r_ipv6_, uint16_t bg_sport_min_, uint16_t bg_sport_max_, uint16_t bg_dport_min_, uint16_t bg_dport_max_,
                                uint16_t first_tagged_delay_, uint16_t num_of_tagged_);
};

class senderParametersLatency : public senderParameters
{
public:
  uint64_t *send_ts; // pointer to the send timestamps
  senderParametersLatency(class senderCommonParameters *cp_, rte_mempool *pkt_pool_, uint8_t eth_id_, const char *direction_,
                          CE_data *CE_array_, struct ether_addr *dst_mac_, struct ether_addr *src_mac_, unsigned var_sport_, unsigned var_dport_,
                          uint16_t preconfigured_port_min_, uint16_t preconfigured_port_max_,
                          uint64_t *send_ts_);
};

class receiverParametersLatency : public receiverParameters
{
public:
  uint16_t num_of_tagged;
  uint64_t *receive_ts; // pointer to the receive timestamps
  receiverParametersLatency(uint64_t finish_receiving_, uint8_t eth_id_, const char *direction_, uint16_t num_of_tagged_, uint64_t *receive_ts_);
};

void evaluateLatency(uint16_t num_of_tagged, uint64_t *send_ts, uint64_t *receive_ts, uint64_t hz, int penalty, const char *direction);

#endif
