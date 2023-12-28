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

// the main class for PDV measurements, adds some features to class Throughput
class Pdv : public Throughput
{
public:
  uint16_t frame_timeout; // if 0, normal PDV measurement is done; if >0, then frames with delay higher then frame_timeout are considered lost

  Pdv() : Throughput(){};                        // default constructor
  int readCmdLine(int argc, const char *argv[]); // reads further one argument: frame_timeout

  // perform pdv measurement
  void measure(uint16_t leftport, uint16_t rightport);
};

// functions to create PDV Frames (and their parts)
struct rte_mbuf *mkPdvFrame4(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                             const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                             const uint32_t *src_ip, uint32_t *dst_ip, unsigned var_sport, unsigned var_dport);

void mkDataPdv(uint8_t *data, uint16_t length);

struct rte_mbuf *mkPdvFrame6(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                             const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                             struct in6_addr *src_ip, struct in6_addr *dst_ip, unsigned var_sport, unsigned var_dport);

class senderParametersPdv : public senderParameters
{
public:
  uint64_t **send_ts;
  senderParametersPdv(class senderCommonParameters *cp_, rte_mempool *pkt_pool_, uint8_t eth_id_, const char *direction_,
                      CE_data *CE_array_, struct ether_addr *dst_mac_, struct ether_addr *src_mac_, unsigned var_sport_, unsigned var_dport_,
                      uint16_t preconfigured_port_min_, uint16_t preconfigured_port_max_,
                      uint64_t **send_ts_);
};

class receiverParametersPdv : public receiverParameters
{
public:
  uint64_t num_frames; // number of all frames, needed for the rte_zmalloc call for allocating receive_ts
  uint16_t frame_timeout;
  uint64_t **receive_ts;
  receiverParametersPdv(uint64_t finish_receiving_, uint8_t eth_id_, const char *direction_,
                        uint64_t num_frames_, uint16_t frame_timeout_, uint64_t **receive_ts_);
};

void evaluatePdv(uint64_t num_of_frames, uint64_t *send_ts, uint64_t *receive_ts, uint64_t hz, uint16_t frame_timeout, int penalty, const char *direction);

#endif
