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

char coresList[101];  // buffer for preparing the list of lcores for DPDK init (like a command line argument)
char numChannels[11]; // buffer for printing the number of memory channels into a string for DPDK init (like a command line argument)

Throughput::Throughput()
{
  // initialize some data members to default or invalid value //Just in case of not setting them in the configuration file and the Tester did not exit
  forward = 1;                   // default value, forward direction is active
  reverse = 1;                   // default value, reverse direction is active
  promisc = 0;                   // default value, promiscuous mode is inactive
  left_sender_cpu = -1;          // MUST be set in the config file if forward != 0
  right_receiver_cpu = -1;       // MUST be set in the config file if forward != 0
  right_sender_cpu = -1;         // MUST be set in the config file if reverse != 0
  left_receiver_cpu = -1;        // MUST be set in the config file if reverse != 0
  memory_channels = 1;           // default value, this value will be set, if not specified in the config file
  fwd_var_sport = 3;             // default value: use pseudorandom change for the source port numbers in the forward direction
  fwd_var_dport = 3;             // default value: use pseudorandom change for the destination port numbers in the forward direction
  fwd_dport_min = 1;             // default value: as recommended by RFC 4814
  fwd_dport_max = 49151;         // default value: as recommended by RFC 4814
  rev_var_sport = 3;             // default value: use pseudorandom change for the source port numbers in the reverse direction
  rev_var_dport = 3;             // default value: use pseudorandom change for the destination port numbers in the reverse direction
  rev_sport_min = 1024;          // default value: as recommended by RFC 4814
  rev_sport_max = 65535;         // default value: as recommended by RFC 4814
  bg_sport_min = 1024;           // default value: as recommended by RFC 4814
  bg_sport_max = 65535;          // default value: as recommended by RFC 4814
  bg_dport_min = 1;              // default value: as recommended by RFC 4814
  bg_dport_max = 49151;          // default value: as recommended by RFC 4814
  
  bmr_ipv6_prefix = {{0x20, 0x01, 0x0d, 0xb8, 0x00, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}; // 2001:db8:ce::
  bmr_ipv6_prefix_length = 51;   // /51
  bmr_ipv4_prefix_length = 24;   // /24
  bmr_EA_length = 13;            // IPv4 Suffix + psid => 13 bits
  dmr_ipv6_prefix = {{0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}; // 64:ff9b::
  dmr_ipv6_prefix_length = 64;   // /64
  

  // some other variables
  dmr_ipv6 = IN6ADDR_ANY_INIT;  
  fwUniqueEAComb = NULL;         
  rvUniqueEAComb = NULL;                                    
  fwCE = NULL;                  
  rvCE = NULL;                  
};

// finds a 'key' (name of a parameter) in the 'line' string
// '#' means comment, leading spaces and tabs are skipped
// return: the starting position of the key, if found; -1 otherwise
int Throughput::findKey(const char *line, const char *key)
{
  int line_len, key_len; // the lenght of the line and of the key
  int pos;               // current position in the line

  line_len = strlen(line);
  key_len = strlen(key);
  for (pos = 0; pos < line_len - key_len; pos++)
  {
    if (line[pos] == '#') // comment
      return -1;
    if (line[pos] == ' ' || line[pos] == '\t')
      continue;
    if (strncmp(line + pos, key, key_len) == 0)
      return pos + strlen(key);
  }
  return -1;
}

// skips leading spaces and tabs, and cuts off tail starting by a space, tab or new line character
// it is needed, because inet_pton cannot read if there is e.g. a trailing '\n'
// WARNING: the input buffer is changed!
char *prune(char *s)
{
  int len, i;

  // skip leading spaces and tabs
  while (*s == ' ' || *s == '\t')
    s++;

  // trim string, if space, tab or new line occurs
  len = strlen(s);
  for (i = 0; i < len; i++)
    if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n')
    {
      s[i] = (char)0;
      break;
    }
  return s;
}

// checks if there is some non comment information in the line
int nonComment(const char *line)
{
  int i;

  for (i = 0; i < LINELEN; i++)
  {
    if (line[i] == '#' || line[i] == '\n')
      return 0; // line is comment or empty
    else if (line[i] == ' ' || line[i] == '\t')
      continue; // skip space or tab, see next char
    else
      return 1; // there is some other character
  }
  // below code should be unreachable
  return 1;
}

// reads the configuration file and stores the information in data members of class Throughput
int Throughput::readConfigFile(const char *filename)
{
  FILE *f; // file descriptor

  char line[LINELEN + 1]; // buffer for reading a line of the input file
  int pos;                // position in the line after the key (parameter name) was found
  uint8_t *m;             // pointer to the MAC address being read
  int line_no;            // line number for error message
  f = fopen(filename, "r");
  if (f == NULL)
  {
    std::cerr << "Input Error: Can't open file '" << filename << "'." << std::endl;
    return -1;
  }
  for (line_no = 1; fgets(line, LINELEN + 1, f); line_no++)
  {
    if ((pos = findKey(line, "Tester-L-IPv6")) >= 0)
    {
      if (inet_pton(AF_INET6, prune(line + pos), reinterpret_cast<void *>(&tester_left_ipv6)) != 1)
      {
        std::cerr << "Input Error: Bad 'Tester-L-IPv6' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "Tester-R-IPv4")) >= 0)
    {
      if (inet_pton(AF_INET, prune(line + pos), reinterpret_cast<void *>(&tester_right_ipv4)) != 1)
      {
        std::cerr << "Input Error: Bad 'Tester-R-IPv4' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "Tester-R-IPv6")) >= 0)
    {
      if (inet_pton(AF_INET6, prune(line + pos), reinterpret_cast<void *>(&tester_right_ipv6)) != 1)
      {
        std::cerr << "Input Error: Bad 'Tester-R-IPv6' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "Tester-L-MAC")) >= 0)
    {
      m = tester_left_mac;
      if (sscanf(line + pos, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) < 6)
      {
        std::cerr << "Input Error: Bad 'Tester-L-MAC' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "Tester-R-MAC")) >= 0)
    {
      m = tester_right_mac;
      if (sscanf(line + pos, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) < 6)
      {
        std::cerr << "Input Error: Bad 'Tester-R-MAC' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "DUT-L-MAC")) >= 0)
    {
      m = dut_left_mac;
      if (sscanf(line + pos, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) < 6)
      {
        std::cerr << "Input Error: Bad 'DUT-L-MAC' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "DUT-R-MAC")) >= 0)
    {
      m = dut_right_mac;
      if (sscanf(line + pos, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) < 6)
      {
        std::cerr << "Input Error: Bad 'DUT-R-MAC' address." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "FW-var-sport")) >= 0)
    {
      sscanf(line + pos, "%u", &fwd_var_sport);
      if (!(fwd_var_sport == 1 || fwd_var_sport == 2 || fwd_var_sport == 3))
      {
        std::cerr << "Input Error: 'FW-var-sport' must be either 1 for increasing, 2 for decreasing, or 3 for random." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "FW-var-dport")) >= 0)
    {
      sscanf(line + pos, "%u", &fwd_var_dport);
      if (!(fwd_var_dport == 1 || fwd_var_dport == 2 || fwd_var_dport == 3))
      {
        std::cerr << "Input Error: 'FW-var-dport' must be either 1 for increasing, 2 for decreasing, or 3 for random." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "RV-var-sport")) >= 0)
    {
      sscanf(line + pos, "%u", &rev_var_sport);
      if (!(rev_var_sport == 1 || rev_var_sport == 2 || rev_var_sport == 3))
      {
        std::cerr << "Input Error: 'RV-var-sport' must be either 1 for increasing, 2 for decreasing, or 3 for random." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "RV-var-dport")) >= 0)
    {
      sscanf(line + pos, "%u", &rev_var_dport);
      if (!(rev_var_dport == 1 || rev_var_dport == 2 || rev_var_dport == 3))
      {
        std::cerr << "Input Error: 'RV-var-dport' must be either 1 for increasing, 2 for decreasing, or 3 for random." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "FW-dport-min")) >= 0)
    {
      if (sscanf(line + pos, "%u", &fwd_dport_min) < 1)
      {
        std::cerr << "Input Error: Unable to read 'FW-dport-min'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "FW-dport-max")) >= 0)
    {
      if (sscanf(line + pos, "%u", &fwd_dport_max) < 1)
      {
        std::cerr << "Input Error: Unable to read 'FW-dport-max'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "RV-sport-min")) >= 0)
    {
      if (sscanf(line + pos, "%u", &rev_sport_min) < 1)
      {
        std::cerr << "Input Error: Unable to read 'RV-sport-min'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "RV-sport-max")) >= 0)
    {
      if (sscanf(line + pos, "%u", &rev_sport_max) < 1)
      {
        std::cerr << "Input Error: Unable to read 'RV-sport-max'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "bg-dport-min")) >= 0)
    {
      if (sscanf(line + pos, "%u", &bg_dport_min) < 1)
      {
        std::cerr << "Input Error: Unable to read 'bg-dport-min'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "bg-dport-max")) >= 0)
    {
      if (sscanf(line + pos, "%u", &bg_dport_max) < 1)
      {
        std::cerr << "Input Error: Unable to read 'bg-dport-max'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "bg-sport-min")) >= 0)
    {
      if (sscanf(line + pos, "%u", &bg_sport_min) < 1)
      {
        std::cerr << "Input Error: Unable to read 'bg-sport-min'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "bg-sport-max")) >= 0)
    {
      if (sscanf(line + pos, "%u", &bg_sport_max) < 1)
      {
        std::cerr << "Input Error: Unable to read 'bg-sport-max'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "NUM-OF-CEs")) >= 0)
    {
      sscanf(line + pos, "%u", &num_of_CEs);
      if (num_of_CEs < 1 || num_of_CEs > 1000000)
      {
        std::cerr << "Input Error: 'NUM-OF-CEs' must be >= 1 and <= 1000000." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "BMR-IPv6-Prefix")) >= 0)
    {
      if (inet_pton(AF_INET6, prune(line + pos), reinterpret_cast<void *>(&bmr_ipv6_prefix)) != 1)
      {
        std::cerr << "Input Error: Bad 'BMR-IPv6-Prefix'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "BMR-IPv6-prefix-length")) >= 0)
    {
      sscanf(line + pos, "%u", &bmr_ipv6_prefix_length);
      if (bmr_ipv6_prefix_length < 1 || bmr_ipv6_prefix_length > 64)
      {
        std::cerr << "Input Error: 'BMR-IPv6-prefix-length' must be >= 1 and <= 64." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "BMR-IPv4-Prefix")) >= 0)
    {
      if (inet_pton(AF_INET, prune(line + pos), reinterpret_cast<void *>(&bmr_ipv4_prefix)) != 1)
      {
        std::cerr << "Input Error: Bad 'BMR-IPv4-Prefix'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "BMR-IPv4-prefix-length")) >= 0)
    {
      sscanf(line + pos, "%u", &bmr_ipv4_prefix_length);
      if (bmr_ipv4_prefix_length < 0 || bmr_ipv4_prefix_length > 32)
      {
        std::cerr << "Input Error: 'BMR-IPv4-prefix-length' must be >= 0 and <= 32." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "BMR-EA-length")) >= 0)
    {
      sscanf(line + pos, "%u", &bmr_EA_length);
      if (bmr_EA_length < 0 || bmr_EA_length > 48)
      { // accoding to RFC 7597 section 5.2
        std::cerr << "Input Error: 'BMR-EA-length' must be >= 0 and <= 48." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "DMR-IPv6-Prefix")) >= 0)
    {
      if (inet_pton(AF_INET6, prune(line + pos), reinterpret_cast<void *>(&dmr_ipv6_prefix)) != 1)
      {
        std::cerr << "Input Error: Bad 'DMR-IPv6-Prefix'." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "DMR-IPv6-prefix-length")) >= 0)
    {
      sscanf(line + pos, "%u", &dmr_ipv6_prefix_length);
      if (dmr_ipv6_prefix_length < 64 || dmr_ipv6_prefix_length > 96)
      { // according to RFC 7599 section 5.1
        std::cerr << "Input Error: 'DMR-IPv6-prefix-length' must be >= 64 and <= 96." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "CPU-FW-Send")) >= 0)
    {
      sscanf(line + pos, "%d", &left_sender_cpu);
      if (left_sender_cpu < 0 || left_sender_cpu >= RTE_MAX_LCORE)
      {
        std::cerr << "Input Error: 'CPU-FW-Send' must be >= 0 and < RTE_MAX_LCORE." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "CPU-FW-Receive")) >= 0)
    {
      sscanf(line + pos, "%d", &right_receiver_cpu);
      if (right_receiver_cpu < 0 || right_receiver_cpu >= RTE_MAX_LCORE)
      {
        std::cerr << "Input Error: 'CPU-FW-Receive' must be >= 0 and < RTE_MAX_LCORE." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "CPU-RV-Send")) >= 0)
    {
      sscanf(line + pos, "%d", &right_sender_cpu);
      if (right_sender_cpu < 0 || right_sender_cpu >= RTE_MAX_LCORE)
      {
        std::cerr << "Input Error: 'CPU-RV-Send' must be >= 0 and < RTE_MAX_LCORE." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "CPU-RV-Receive")) >= 0)
    {
      sscanf(line + pos, "%d", &left_receiver_cpu);
      if (left_receiver_cpu < 0 || left_receiver_cpu >= RTE_MAX_LCORE)
      {
        std::cerr << "Input Error: 'CPU-RV-Receive' must be >= 0 and < RTE_MAX_LCORE." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "Mem-Channels")) >= 0)
    {
      sscanf(line + pos, "%hhu", &memory_channels);
      if (memory_channels <= 0)
      {
        std::cerr << "Input Error: 'Mem-Channels' must be > 0." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "FW")) >= 0)
    {
      sscanf(line + pos, "%d", &forward);
      if (!(forward == 0 || forward == 1))
      {
        std::cerr << "Input Error: 'FW' must be either 0 for inactive or 1 for active." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "RV")) >= 0)
    {
      sscanf(line + pos, "%d", &reverse);
      if (!(reverse == 0 || reverse == 1))
      {
        std::cerr << "Input Error: 'RV' must be either 0 for inactive or 1 for active." << std::endl;
        return -1;
      }
    }
    else if ((pos = findKey(line, "Promisc")) >= 0)
    {
      sscanf(line + pos, "%d", &promisc);
      if (!(promisc == 0 || promisc == 1))
      {
        std::cerr << "Input Error: 'Promisc' must be either 0 for inactive or 1 for active." << std::endl;
        return -1;
      }
    }
    else if (nonComment(line))
    { // It may be too strict!
      std::cerr << "Input Error: Cannot interpret '" << filename << "' line " << line_no << ":" << std::endl;
      std::cerr << line << std::endl;
      return -1;
    }
  }
  fclose(f);
  // check if at least one direction is active
  if (forward == 0 && reverse == 0)
  {
    std::cerr << "Input Error: No active direction was specified." << std::endl;
    return -1;
  }
  // check if the necessary lcores were specified
  if (forward)
  {
    if (left_sender_cpu < 0)
    {
      std::cerr << "Input Error: No 'CPU-FW-Send' was specified." << std::endl;
      return -1;
    }
    if (right_receiver_cpu < 0)
    {
      std::cerr << "Input Error: No 'CPU-FW-Receive' was specified." << std::endl;
      return -1;
    }
  }
  if (reverse)
  {
    if (right_sender_cpu < 0)
    {
      std::cerr << "Input Error: No 'CPU-RV-Send' was specified." << std::endl;
      return -1;
    }
    if (left_receiver_cpu < 0)
    {
      std::cerr << "Input Error: No 'CPU-RV-Receive' was specified." << std::endl;
      return -1;
    }
  }

  return 0;
}

// reads the command line arguments and stores the information in data members of class Throughput
// It may be called only AFTER the execution of readConfigFile
int Throughput::readCmdLine(int argc, const char *argv[])
{
  if (argc < 7)
  {
    printf("argc : %d\n", argc);
    std::cerr << "Input Error: Too few command line arguments." << std::endl;
    return -1;
  }
  if (sscanf(argv[1], "%hu", &ipv6_frame_size) != 1 || ipv6_frame_size < 84 || ipv6_frame_size > 1538)
  {
    std::cerr << "Input Error: IPv6 frame size must be between 84 and 1538." << std::endl;
    return -1;
  }
  // Further checking of the frame size will be done, when n and m are read.
  ipv4_frame_size = ipv6_frame_size - 20;
  if (sscanf(argv[2], "%u", &frame_rate) != 1 || frame_rate < 1 || frame_rate > 14880952)
  {
    // 14,880,952 is the maximum frame rate for 10Gbps Ethernet using 64-byte frame size
    std::cerr << "Input Error: Frame rate must be between 1 and 14880952." << std::endl;
    return -1;
  }
  if (sscanf(argv[3], "%hu", &test_duration) != 1 || test_duration < 1 || test_duration > 3600)
  {
    std::cerr << "Input Error: Test duration must be between 1 and 3600." << std::endl;
    return -1;
  }
  if (sscanf(argv[4], "%hu", &stream_timeout) != 1 || stream_timeout > 60000)
  {
    std::cerr << "Input Error: Stream timeout must be between 0 and 60000." << std::endl;
    return -1;
  }
  if (sscanf(argv[5], "%u", &n) != 1 || n < 2)
  {
    std::cerr << "Input Error: The value of 'n' must be at least 2." << std::endl;
    return -1;
  }
  if (sscanf(argv[6], "%u", &m) != 1)
  {
    std::cerr << "Input Error: Cannot read the value of 'm'." << std::endl;
    return -1;
  }

  return 0;
}

// Initializes DPDK EAL, starts network ports, creates and sets up TX/RX queues, checks NUMA localty and TSC synchronization of lcores, and prepare MAP parameters
int Throughput::init(const char *argv0, uint16_t leftport, uint16_t rightport)
{
  const char *rte_argv[6];                                                     // parameters for DPDK EAL init, e.g.: {NULL, "-l", "4,5,6,7", "-n", "2", NULL};
  int rte_argc = static_cast<int>(sizeof(rte_argv) / sizeof(rte_argv[0])) - 1; // argc value for DPDK EAL init
  struct rte_eth_conf cfg_port;                                                // for configuring the Ethernet ports
  struct rte_eth_link link_info;                                               // for retrieving link info by rte_eth_link_get()
  int trials;                                                                  // cycle variable for port state checking

  // prepare 'command line' arguments for rte_eal_init
  rte_argv[0] = argv0; // program name
  rte_argv[1] = "-l";  // list of lcores will follow
  // Only lcores for the active directions are to be included (at least one of them MUST be non-zero)
  if (forward && reverse)
  {
    // both directions are active
    snprintf(coresList, 101, "0,%d,%d,%d,%d", left_sender_cpu, right_receiver_cpu, right_sender_cpu, left_receiver_cpu);
  }
  else if (forward)
    snprintf(coresList, 101, "0,%d,%d", left_sender_cpu, right_receiver_cpu); // only forward (left to right) is active
  else
    snprintf(coresList, 101, "0,%d,%d", right_sender_cpu, left_receiver_cpu); // only reverse (right to left) is active
  rte_argv[2] = coresList;
  rte_argv[3] = "-n";
  snprintf(numChannels, 11, "%hhu", memory_channels);
  rte_argv[4] = numChannels;
  rte_argv[5] = 0;

  if (rte_eal_init(rte_argc, const_cast<char **>(rte_argv)) < 0)
  {
    std::cerr << "Error: DPDK RTE initialization failed, Tester exits." << std::endl;
    return -1;
  }

  if (!rte_eth_dev_is_valid_port(leftport))
  {
    std::cerr << "Error: Network port #" << leftport << " provided as Left Port is not available, Tester exits." << std::endl;
    return -1;
  }

  if (!rte_eth_dev_is_valid_port(rightport))
  {
    std::cerr << "Error: Network port #" << rightport << " provided as Right Port is not available, Tester exits." << std::endl;
    return -1;
  }

  // prepare for configuring the Ethernet ports
  memset(&cfg_port, 0, sizeof(cfg_port));   // e.g. no CRC generation offloading, etc. (May be improved later!)
  cfg_port.txmode.mq_mode = ETH_MQ_TX_NONE; // no multi queues
  cfg_port.rxmode.mq_mode = ETH_MQ_RX_NONE; // no multi queues

  if (rte_eth_dev_configure(leftport, 1, 1, &cfg_port) < 0)
  {
    std::cerr << "Error: Cannot configure network port #" << leftport << " provided as Left Port, Tester exits." << std::endl;
    return -1;
  }

  if (rte_eth_dev_configure(rightport, 1, 1, &cfg_port) < 0)
  {
    std::cerr << "Error: Cannot configure network port #" << rightport << " provided as Right Port, Tester exits." << std::endl;
    return -1;
  }

  // Important remark: with no regard whether actual test will be performed in the forward or reverese direcetion,
  // all TX and RX queues MUST be set up properly, otherwise rte_eth_dev_start() will cause segmentation fault.
  // Sender pool size calculation uses 0 instead of num_{left,right}_nets, when no actual frame sending is needed.

  // calculate packet pool sizes and then create the pools
  int left_sender_pool_size = senderPoolSize();
  int right_sender_pool_size = senderPoolSize();
  int receiver_pool_size = PORT_RX_QUEUE_SIZE + 2 * MAX_PKT_BURST + 100; // While one of them is processed, the other one is being filled.

  pkt_pool_left_sender = rte_pktmbuf_pool_create("pp_left_sender", left_sender_pool_size, PKTPOOL_CACHE, 0,
                                                 RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(left_sender_cpu));
  if (!pkt_pool_left_sender)
  {
    std::cerr << "Error: Cannot create packet pool for Left Sender, Tester exits." << std::endl;
    return -1;
  }
  pkt_pool_right_receiver = rte_pktmbuf_pool_create("pp_right_receiver", receiver_pool_size, PKTPOOL_CACHE, 0,
                                                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(right_receiver_cpu));
  if (!pkt_pool_right_receiver)
  {
    std::cerr << "Error: Cannot create packet pool for Right Receiver, Tester exits." << std::endl;
    return -1;
  }

  pkt_pool_right_sender = rte_pktmbuf_pool_create("pp_right_sender", right_sender_pool_size, PKTPOOL_CACHE, 0,
                                                  RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(right_sender_cpu));
  if (!pkt_pool_right_sender)
  {
    std::cerr << "Error: Cannot create packet pool for Right Sender, Tester exits." << std::endl;
    return -1;
  }
  pkt_pool_left_receiver = rte_pktmbuf_pool_create("pp_left_receiver", receiver_pool_size, PKTPOOL_CACHE, 0,
                                                   RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(left_receiver_cpu));
  if (!pkt_pool_left_receiver)
  {
    std::cerr << "Error: Cannot create packet pool for Left Receiver, Tester exits." << std::endl;
    return -1;
  }

  // set up the TX/RX queues
  if (rte_eth_tx_queue_setup(leftport, 0, PORT_TX_QUEUE_SIZE, rte_eth_dev_socket_id(leftport), NULL) < 0)
  {
    std::cerr << "Error: Cannot setup TX queue for Left Sender, Tester exits." << std::endl;
    return -1;
  }
  if (rte_eth_rx_queue_setup(rightport, 0, PORT_RX_QUEUE_SIZE, rte_eth_dev_socket_id(rightport), NULL, pkt_pool_right_receiver) < 0)
  {
    std::cerr << "Error: Cannot setup RX queue for Right Receiver, Tester exits." << std::endl;
    return -1;
  }
  if (rte_eth_tx_queue_setup(rightport, 0, PORT_TX_QUEUE_SIZE, rte_eth_dev_socket_id(rightport), NULL) < 0)
  {
    std::cerr << "Error: Cannot setup TX queue for Right Sender, Tester exits." << std::endl;
    return -1;
  }
  if (rte_eth_rx_queue_setup(leftport, 0, PORT_RX_QUEUE_SIZE, rte_eth_dev_socket_id(leftport), NULL, pkt_pool_left_receiver) < 0)
  {
    std::cerr << "Error: Cannot setup RX queue for Left Receiver, Tester exits." << std::endl;
    return -1;
  }

  // start the Ethernet ports
  if (rte_eth_dev_start(leftport) < 0)
  {
    std::cerr << "Error: Cannot start network port #" << leftport << " provided as Left Port, Tester exits." << std::endl;
    return -1;
  }
  if (rte_eth_dev_start(rightport) < 0)
  {
    std::cerr << "Error: Cannot start network port #" << rightport << " provided as Right Port, Tester exits." << std::endl;
    return -1;
  }

  if (promisc)
  {
    rte_eth_promiscuous_enable(leftport);
    rte_eth_promiscuous_enable(rightport);
  }

  // check links' states (wait for coming up), try maximum MAX_PORT_TRIALS times
  trials = 0;
  do
  {
    if (trials++ == MAX_PORT_TRIALS)
    {
      std::cerr << "Error: Left Ethernet port is DOWN, Tester exits." << std::endl;
      return -1;
    }
    rte_eth_link_get(leftport, &link_info);
  } while (link_info.link_status == ETH_LINK_DOWN);
  trials = 0;
  do
  {
    if (trials++ == MAX_PORT_TRIALS)
    {
      std::cerr << "Error: Right Ethernet port is DOWN, Tester exits." << std::endl;
      return -1;
    }
    rte_eth_link_get(rightport, &link_info);
  } while (link_info.link_status == ETH_LINK_DOWN);

  // Some sanity checks: NUMA node of the cores and of the NICs are matching or not...
  if (numa_available() == -1)
    std::cout << "Info: This computer does not support NUMA." << std::endl;
  else
  {
    if (numa_num_configured_nodes() == 1)
      std::cout << "Info: Only a single NUMA node is configured, there is no possibilty for mismatch." << std::endl;
    else
    {
      if (forward)
      {
        numaCheck(leftport, "Left", left_sender_cpu, "Left Sender");
        numaCheck(rightport, "Right", right_receiver_cpu, "Right Receiver");
      }
      if (reverse)
      {
        numaCheck(rightport, "Right", right_sender_cpu, "Right Sender");
        numaCheck(leftport, "Left", left_receiver_cpu, "Left Receiver");
      }
    }
  }

  // Some sanity checks: TSCs of the used cores are synchronized or not...
  if (forward)
  {
    check_tsc(left_sender_cpu, "Left Sender");
    check_tsc(right_receiver_cpu, "Right Receiver");
  }
  if (reverse)
  {
    check_tsc(right_sender_cpu, "Right Sender");
    check_tsc(left_receiver_cpu, "Left Receiver");
  }

  // prepare further values for testing
  hz = rte_get_timer_hz();                                                       // number of clock cycles per second
  start_tsc = rte_rdtsc() + hz * START_DELAY / 1000;                             // Each active sender starts sending at this time
  finish_receiving = start_tsc + hz * (test_duration + stream_timeout / 1000.0); // Each receiver stops at this time

  // producing some important values from the BMR configuration parameters for the next tasks (e.g., generating the pseudorandom EA combinations)
  bmr_ipv4_suffix_length = 32 - bmr_ipv4_prefix_length;
  psid_length = bmr_EA_length - bmr_ipv4_suffix_length;
  num_of_port_sets = pow(2.0, psid_length);
  num_of_ports = (uint16_t)(65536.0 / num_of_port_sets); // 65536.0 denotes the total number of port possibilities can be there in the 16-bit udp port number(i.e., 2 ^ 16)
  int num_of_suffixes = pow(2.0, bmr_ipv4_suffix_length)-2; //-2 to exclude the subnet and broadcast addresses
  int max_num_of_CEs = (num_of_suffixes * num_of_port_sets); //maximum possible number of CEs based on the number of EA-bits

  if (num_of_CEs > max_num_of_CEs){
    std::cerr << "Config Error: The number of CEs ("<< num_of_CEs <<") to be simulated exceeds the maximum number that EA-bits allow (" << max_num_of_CEs << ")" << std::endl;
    return -1;
  }
  
  // pre-generate pseudorandom EA-bits combinations 
  //and save them in a NUMA local memory (of the same memory of the sender core for fast access)
  // For this purpose, we used rte_eal_remote_launch() and pack parameters for it

  // prepare the parameters for the randomPermutationGenerator48
    randomPermutationGeneratorParameters48 pars;
    pars.ip4_suffix_length = bmr_ipv4_suffix_length;
    pars.psid_length = psid_length;
    pars.hz = rte_get_timer_hz(); // number of clock cycles per second;
    
    if (forward)
      {
        pars.direction = "forward"; 
        pars.addr_of_arraypointer = &fwUniqueEAComb;
        // start randomPermutationGenerator32
        if ( rte_eal_remote_launch(randomPermutationGenerator48, &pars, left_sender_cpu ) )
          std::cerr << "Error: could not start randomPermutationGenerator48() for pre-generating unique EA-bits combinations at the " << pars.direction << " sender" << std::endl;
        rte_eal_wait_lcore(left_sender_cpu);
      }
    if (reverse)
      {
        pars.direction = "reverse";
        pars.addr_of_arraypointer = &rvUniqueEAComb;
        // start randomPermutationGenerator32
        if ( rte_eal_remote_launch(randomPermutationGenerator48, &pars, right_sender_cpu ) )
          std::cerr << "Error: could not start randomPermutationGenerator48() for pre-generating unique EA-bits combinations at the " << pars.direction << " sender" << std::endl;
        rte_eal_wait_lcore(right_sender_cpu);
      }

  // pre-generate the array of CEs Data (MAP addresses and others) 
  //and save it in a NUMA local memory (of the same memory of the sender core for fast access)
  // For this purpose, we used rte_eal_remote_launch() and pack parameters for it

  CEArrayBuilderParameters param;
  param.bmr_ipv4_suffix_length = bmr_ipv4_suffix_length; 
  param.psid_length =  psid_length;            
  param.num_of_CEs = num_of_CEs;             
  param.bmr_ipv6_prefix = bmr_ipv6_prefix; 
  param.bmr_ipv6_prefix_length = bmr_ipv6_prefix_length;  
  param.bmr_ipv4_prefix = bmr_ipv4_prefix;        
  param.hz = rte_get_timer_hz(); // number of clock cycles per second			
  
  if (forward)
    {
      param.direction = "forward"; 
      param.UniqueEAComb = fwUniqueEAComb;       
      param.addr_of_arraypointer = &fwCE;
      // start randomPermutationGenerator32
        if ( rte_eal_remote_launch(buildCEArray, &param, left_sender_cpu ) )
          std::cerr << "Error: could not start buildCEArray() for pre-generating the array of CEs data at the " << param.direction << " sender" << std::endl;
        rte_eal_wait_lcore(left_sender_cpu);
      }
  if (reverse)
      {
        param.direction = "reverse";
        param.UniqueEAComb = rvUniqueEAComb;       
        param.addr_of_arraypointer = &rvCE;
        // start randomPermutationGenerator32
        if ( rte_eal_remote_launch(buildCEArray, &param, right_sender_cpu ) )
             std::cerr << "Error: could not start buildCEArray() for pre-generating the array of CEs data at the " << param.direction << " sender" << std::endl;
        rte_eal_wait_lcore(right_sender_cpu);
      }

  // Construct the DMR ipv6 address (It will be the destination address in the forward direction in case of the foreground traffic)
 // Based on section 2.2 of RFC 6052, The possible DMR prefix length are 32, 40, 48, 56, 64, and 96.
 //and bits 64 to 71 of the address are reserved and should be 0 for all prefix cases except 96.
 //When using a /96 Network-Specific Prefix, the administrators MUST ensure that the bits 64 to 71 are set to zero.
 //Please refer to the figure of section 2.2 of RFC 6052 for more information.
 rte_memcpy(dmr_ipv6.s6_addr, dmr_ipv6_prefix.s6_addr, 16);

 int num_octets_before_u = (64-dmr_ipv6_prefix_length)/8;
 int num_octets_after_u = 4 - num_octets_before_u;
 if (num_octets_before_u < 0) // /96 prefix. There are no u bits
  for (int i = 0; i < 4; i++)
    dmr_ipv6.s6_addr[15 - i] = (unsigned char)(ntohl(tester_right_ipv4) >> (i * 8));
 else { // /32, /40, /48, /56, or /64 prefix. There are u bits (64-72)
  for (int i = 0; i < num_octets_before_u; i++)
    dmr_ipv6.s6_addr[7 - i] = (unsigned char)(ntohl(tester_right_ipv4) >> ((i + num_octets_after_u) * 8));
  // dmr_ipv6.s6_addr[8] = u bits = 0
  for (int i = 0; i < num_octets_after_u; i++)
    dmr_ipv6.s6_addr[9 + i] = (unsigned char)(ntohl(tester_right_ipv4) >> (((num_octets_after_u - 1) - i) * 8));
 }

  return 0;
}

// calculates sender pool size, it is a virtual member function, redefined in derived classes
int Throughput::senderPoolSize()
{
  return 2 * N + PORT_TX_QUEUE_SIZE + 100; // 2*: fg. and bg. Test Frames
  // if varport then everything exists in N copies, see the definition of N
}

// checks NUMA localty: is the NUMA node of network port and CPU the same?
void Throughput::numaCheck(uint16_t port, const char *port_side, int cpu, const char *cpu_name)
{
  int n_port, n_cpu;
  n_port = rte_eth_dev_socket_id(port);
  n_cpu = numa_node_of_cpu(cpu);
  if (n_port == n_cpu)
    std::cout << "Info: " << port_side << " port and " << cpu_name << " CPU core belong to the same NUMA node: " << n_port << std::endl;
  else
    std::cout << "Warning: " << port_side << " port and " << cpu_name << " CPU core belong to NUMA nodes " << n_port << ", " << n_cpu << ", respectively." << std::endl;
}

// reports the TSC of the core (in the variable pointed by the input parameter), on which it is running
int report_tsc(void *par)
{
  *(uint64_t *)par = rte_rdtsc();
  return 0;
}

// checks if the TSC of the given lcore is synchronized with that of the main core
// Note that TSCs of different pysical CPUs may be different, which would prevent maptperf from working correctly!
void check_tsc(int cpu, const char *cpu_name)
{
  uint64_t tsc_before, tsc_reported, tsc_after;

  tsc_before = rte_rdtsc();
  if (rte_eal_remote_launch(report_tsc, &tsc_reported, cpu))
    rte_exit(EXIT_FAILURE, "Error: could not start TSC checker on core #%i for %s!\n", cpu, cpu_name);
  rte_eal_wait_lcore(cpu);
  tsc_after = rte_rdtsc();
  if (tsc_reported < tsc_before || tsc_reported > tsc_after)
    rte_exit(EXIT_FAILURE, "Error: TSC of core #%i for %s is not synchronized with that of the main core!\n", cpu, cpu_name);
}

// creates an IPv4 Test Frame using several helper functions
struct rte_mbuf *mkTestFrame4(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                              const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                              const uint32_t *src_ip, uint32_t *dst_ip, unsigned var_sport, unsigned var_dport)
{
  // printf("inside mkTestFrame4: the beginning\n");
  struct rte_mbuf *pkt_mbuf = rte_pktmbuf_alloc(pkt_pool); // message buffer for the Test Frame
  if (!pkt_mbuf)
    rte_exit(EXIT_FAILURE, "Error: %s sender can't allocate a new mbuf for the Test Frame! \n", direction);
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
  mkData(udp_data, data_length);
  udp_hd->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hd); // UDP checksum is calculated and set
  ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);               // IPv4 header checksum is set now
  return pkt_mbuf;
}

// Please refer to RFC 2544 Appendx C.2.6.4 Test Frames for the values to be set in the test frames.

// creates and Ethernet header
void mkEthHeader(struct ether_hdr *eth, const struct ether_addr *dst_mac, const struct ether_addr *src_mac, const uint16_t ether_type)
{
  rte_memcpy(&eth->d_addr, dst_mac, sizeof(struct ether_hdr));
  rte_memcpy(&eth->s_addr, src_mac, sizeof(struct ether_hdr));
  eth->ether_type = htons(ether_type);
}

// creates an IPv4 header
void mkIpv4Header(struct ipv4_hdr *ip, uint16_t length, const uint32_t *src_ip, uint32_t *dst_ip)
{
  ip->version_ihl = 0x45; // Version: 4, IHL: 20/4=5
  ip->type_of_service = 0;
  ip->total_length = htons(length);
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 0x0A;
  ip->next_proto_id = 0x11; // UDP
  ip->hdr_checksum = 0;
  rte_memcpy(&ip->src_addr, src_ip, 4);
  rte_memcpy(&ip->dst_addr, dst_ip, 4);
  // May NOT be set now, only after the UDP header checksum calculation: ip->hdr_checksum = rte_ipv4_cksum(ip);
}

// creates a UDP header
void mkUdpHeader(struct udp_hdr *udp, uint16_t length, unsigned var_sport, unsigned var_dport)
{
  udp->src_port = htons(var_sport ? 0 : 0xC020); // set to 0 if source port number will change, otherwise RFC 2544 Test Frame format
  udp->dst_port = htons(var_dport ? 0 : 0x0007); // set to 0 if destination port number will change, otherwise RFC 2544 Test Frame format
  udp->dgram_len = htons(length);
  udp->dgram_cksum = 0; // Checksum is set to 0 now.
  // UDP checksum is calculated later.
}

// fills the data field of the Test Frame
void mkData(uint8_t *data, uint16_t length)
{
  unsigned i;
  uint8_t identify[8] = {'I', 'D', 'E', 'N', 'T', 'I', 'F', 'Y'}; // Identification of the Test Frames
  uint64_t *id = (uint64_t *)identify;
  *(uint64_t *)data = *id;
  data += 8;
  length -= 8;
  for (i = 0; i < length; i++)
    data[i] = i % 256;
}

// creates an IPv6 Test Frame using several helper functions
struct rte_mbuf *mkTestFrame6(uint16_t length, rte_mempool *pkt_pool, const char *direction,
                              const struct ether_addr *dst_mac, const struct ether_addr *src_mac,
                              struct in6_addr *src_ip, struct in6_addr *dst_ip, unsigned var_sport, unsigned var_dport)
{
  struct rte_mbuf *pkt_mbuf = rte_pktmbuf_alloc(pkt_pool); // message buffer for the Test Frame
  if (!pkt_mbuf)
    rte_exit(EXIT_FAILURE, "Error: %s sender can't allocate a new mbuf for the Test Frame! \n", direction);
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
  mkData(udp_data, data_length);
  udp_hd->dgram_cksum = rte_ipv6_udptcp_cksum(ip_hdr, udp_hd); // UDP checksum is calculated and set
  return pkt_mbuf;
}

// creates and IPv6 header
void mkIpv6Header(struct ipv6_hdr *ip, uint16_t length, struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
  ip->vtc_flow = htonl(0x60000000); // Version: 6, Traffic class: 0, Flow label: 0
  ip->payload_len = htons(length - sizeof(ipv6_hdr));
  ip->proto = 0x11; // UDP
  ip->hop_limits = 0x0A;
  rte_mov16((uint8_t *)&ip->src_addr, (uint8_t *)src_ip);
  rte_mov16((uint8_t *)&ip->dst_addr, (uint8_t *)dst_ip);
}

// concatenates two uint64_t values to form an IPv6 address
// It is used to concatenate the end user IPv6 prefix and the interface ID to form the MAP address
struct in6_addr concatenate(uint64_t in1, uint64_t in2)
{

  unsigned char out[16] = {(unsigned char)(in1 >> 56), (unsigned char)(in1 >> 48), (unsigned char)(in1 >> 40), (unsigned char)(in1 >> 32),
                           (unsigned char)(in1 >> 24), (unsigned char)(in1 >> 16), (unsigned char)(in1 >> 8), (unsigned char)in1,
                           (unsigned char)(in2 >> 56), (unsigned char)(in2 >> 48), (unsigned char)(in2 >> 40), (unsigned char)(in2 >> 32),
                           (unsigned char)(in2 >> 24), (unsigned char)(in2 >> 16), (unsigned char)(in2 >> 8), (unsigned char)in2};
  struct in6_addr out_addr = IN6ADDR_ANY_INIT;
  rte_memcpy(out_addr.s6_addr, out, sizeof(out));

  return out_addr;
}

// sends Test Frames for throughput (or frame loss rate) measurement
int send(void *par)
{
  //  collecting input parameters:
  class senderParameters *p = (class senderParameters *)par;
  class senderCommonParameters *cp = p->cp;

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
    
  
  // implementation of varying port numbers recommended by RFC 4814 https://tools.ietf.org/html/rfc4814#section-4.5
  // RFC 4814 requires pseudorandom port numbers, increasing and decreasing ones are our additional, non-stantard solutions
  // always one of the same N pre-prepared foreground or background frames is updated and sent,
  // source and/or destination IP addresses and port number(s), and UDP and IPv4 header checksum are updated
  // N size arrays are used to resolve the write after send problem

  //some worker variables
  int i;                                                       // cycle variable for the above mentioned purpose: takes {0..N-1} values
  int current_CE;                                              // index variable to the current simulated CE in the CE_array
  uint16_t psid;                                               // working variable for the pseudorandomly enumerated PSID of the currently simulated CE
  struct rte_mbuf *fg_pkt_mbuf[N], *bg_pkt_mbuf[N], *pkt_mbuf; // pointers of message buffers for fg. and bg. Test Frames
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

  // creating buffers of template test frames
 for (i = 0; i < N; i++)
  {

    // create a foreground Test Frame
    if (direction == "reverse")
    {

      fg_pkt_mbuf[i] = mkTestFrame4(ipv4_frame_size, pkt_pool, direction, dst_mac, src_mac, src_ipv4, dst_ipv4, var_sport, var_dport);
      pkt = rte_pktmbuf_mtod(fg_pkt_mbuf[i], uint8_t *); // Access the Test Frame in the message buffer
      // the source ipv4 address will not be manipulated as it will permenantly be the tester-right-ipv4 (extracted from the dmr-ipv6 as done above)
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

  //  arrays to store the minimum and maximum possible source and destination port numbers in each port set.
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

    // set the initial values of port numbers for each port set, depending whether they will be increased (1) or decreased (2)
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
        ip_chksum = ((ip_chksum & 0xffff0000) >> 16) + (ip_chksum & 0xffff); // calculate 16-bit one's complement sum
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

    current_CE = (current_CE + 1) % num_of_CEs; // proceed to the next CE element in the CE array
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

// receives Test Frames for throughput (or frame loss rate) measurements
// Offsets from the start of the Ethernet Frame:
// EtherType: 6+6=12
// IPv6 Next header: 14+6=20, UDP Data for IPv6: 14+40+8=62
// IPv4 Protolcol: 14+9=23, UDP Data for IPv4: 14+20+8=42
int receive(void *par)
{
  // collecting input parameters:
  class receiverParameters *p = (class receiverParameters *)par;
  uint64_t finish_receiving = p->finish_receiving;
  uint8_t eth_id = p->eth_id;
  const char *direction = p->direction;

  // further local variables
  int frames, i;
  struct rte_mbuf *pkt_mbufs[MAX_PKT_BURST];                      // pointers for the mbufs of received frames
  uint16_t ipv4 = htons(0x0800);                                  // EtherType for IPv4 in Network Byte Order
  uint16_t ipv6 = htons(0x86DD);                                  // EtherType for IPv6 in Network Byte Order
  uint8_t identify[8] = {'I', 'D', 'E', 'N', 'T', 'I', 'F', 'Y'}; // Identificion of the Test Frames
  uint64_t *id = (uint64_t *)identify;
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
          received++;
      }
      else if (*(uint16_t *)&pkt[12] == ipv4)
      { /* IPv4 */
         /* check if IPv4 Next Header is UDP, and the first 8 bytes of UDP data is 'IDENTIFY' */
        if (likely(pkt[23] == 17 && *(uint64_t *)&pkt[42] == *id))
          received++;
      }
      rte_pktmbuf_free(pkt_mbufs[i]);
    }
  }
  printf("%s frames received: %lu\n", direction, received);
  return received;
}

// performs throughput (or frame loss rate) measurement
void Throughput::measure(uint16_t leftport, uint16_t rightport)
{
  // set common parameters for senders
  senderCommonParameters scp(ipv6_frame_size, ipv4_frame_size, frame_rate, test_duration, n, m, hz, start_tsc,
                             num_of_CEs, num_of_port_sets, num_of_ports, &tester_left_ipv6, &tester_right_ipv4, &dmr_ipv6, &tester_right_ipv6,
                             bg_sport_min, bg_sport_max, bg_dport_min, bg_dport_max
                             );

  if (forward)
  { // Left to right direction is active
    
    // set individual parameters for the left sender
    // Initialize the parameter class instance
    senderParameters spars(&scp, pkt_pool_left_sender, leftport, "forward", fwCE, (ether_addr *)dut_left_mac, (ether_addr *)tester_left_mac, 
                           fwd_var_sport, fwd_var_dport, fwd_dport_min, fwd_dport_max);

    // start left sender
    if (rte_eal_remote_launch(send, &spars, left_sender_cpu))
      std::cout << "Error: could not start Left Sender." << std::endl;

    // set parameters for the right receiver
    receiverParameters rpars(finish_receiving, rightport, "forward");

    // start right receiver
    if (rte_eal_remote_launch(receive, &rpars, right_receiver_cpu))
      std::cout << "Error: could not start Right Receiver." << std::endl;
  }

  if (reverse)
  { // Right to Left direction is active
    
    // set individual parameters for the right sender
    // Initialize the parameter class instance
    senderParameters spars(&scp, pkt_pool_right_sender, rightport, "reverse", rvCE, (ether_addr *)dut_right_mac, (ether_addr *)tester_right_mac,
                           rev_var_sport, rev_var_dport, rev_sport_min, rev_sport_max);

    // start right sender
    if (rte_eal_remote_launch(send, &spars, right_sender_cpu))
      std::cout << "Error: could not start Right Sender." << std::endl;

    // set parameters for the left receiver
    receiverParameters rpars(finish_receiving, leftport, "reverse");

    // start left receiver
    if (rte_eal_remote_launch(receive, &rpars, left_receiver_cpu))
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
  if (fwCE)
    rte_free(fwCE); // release the CEs data memory at the forward sender
  if (rvCE)
    rte_free(rvCE); // release the CEs data memory at the reverse sender
  if (fwUniqueEAComb) 
    rte_free(fwUniqueEAComb);	// release the memory of the unique EA-bits combinations at the forward sender
  if (rvUniqueEAComb) 
    rte_free(rvUniqueEAComb);	// release the memory of the unique EA-bits combinations at the reverse sender
  std::cout << "Info: Test finished." << std::endl;
}

// sets the values of the data fields
senderCommonParameters::senderCommonParameters(uint16_t ipv6_frame_size_, uint16_t ipv4_frame_size_, uint32_t frame_rate_, uint16_t test_duration_,
                                               uint32_t n_, uint32_t m_, uint64_t hz_, uint64_t start_tsc_, uint32_t num_of_CEs_,
                                               uint16_t num_of_port_sets_, uint16_t num_of_ports_, struct in6_addr *tester_l_ipv6_, uint32_t *tester_r_ipv4_,
                                               struct in6_addr *dmr_ipv6_, struct in6_addr *tester_r_ipv6_,
                                               uint16_t bg_sport_min_, uint16_t bg_sport_max_, uint16_t bg_dport_min_, uint16_t bg_dport_max_
                                               )
{

  ipv6_frame_size = ipv6_frame_size_;
  ipv4_frame_size = ipv4_frame_size_;
  frame_rate = frame_rate_;
  test_duration = test_duration_;
  n = n_;
  m = m_;
  hz = hz_;
  start_tsc = start_tsc_;
  num_of_CEs = num_of_CEs_;
  num_of_port_sets = num_of_port_sets_;
  num_of_ports = num_of_ports_;
  tester_l_ipv6 = tester_l_ipv6_;
  tester_r_ipv4 = tester_r_ipv4_;
  dmr_ipv6 = dmr_ipv6_;
  tester_r_ipv6 = tester_r_ipv6_;
  bg_sport_min = bg_sport_min_;
  bg_sport_max = bg_sport_max_;
  bg_dport_min = bg_dport_min_;
  bg_dport_max = bg_dport_max_;
}

// sets the values of the data fields
senderParameters::senderParameters(class senderCommonParameters *cp_, rte_mempool *pkt_pool_, uint8_t eth_id_, const char *direction_,
                                   CE_data *CE_array_, struct ether_addr *dst_mac_, struct ether_addr *src_mac_, unsigned var_sport_, unsigned var_dport_,
                                   uint16_t preconfigured_port_min_, uint16_t preconfigured_port_max_
                                   )
{
  cp = cp_;
  pkt_pool = pkt_pool_;
  eth_id = eth_id_;
  direction = direction_;
  CE_array = CE_array_;
  dst_mac = dst_mac_;
  src_mac = src_mac_;
  var_sport = var_sport_;
  var_dport = var_dport_;
  preconfigured_port_min = preconfigured_port_min_;
  preconfigured_port_max = preconfigured_port_max_;
}

// sets the values of the data fields
receiverParameters::receiverParameters(uint64_t finish_receiving_, uint8_t eth_id_, const char *direction_)
{
  finish_receiving = finish_receiving_;
  eth_id = eth_id_;
  direction = direction_;
}

// helper function to the generator function below
void randomPermutation48(EAbits48 *array, uint8_t ip4_suffix_length, uint8_t psid_length){
  uint32_t suffix_field, suffix_min, x; // x for suffix coordinate
  uint16_t psid_field, psid_min, y; // y for psid coordinate
  uint32_t xsize = pow(2.0,ip4_suffix_length);
  uint32_t ysize = pow(2.0,psid_length); // 
  uint64_t size = (xsize-2)*(ysize);  // size of the entire array / -2 to exclude all 0's case(subnet addr) and all 1's case(broadcast addr)
  uint64_t index, random; 	// index and random variables

  // prepare random permutation using Fisher–Yates shuffle, as implemented by Durstenfeld (in-place)
  // http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_.22inside-out.22_algorithm

  // random number infrastructure is taken from: https://en.cppreference.com/w/cpp/numeric/random/uniform_real_distribution
  // MT64 is used because of https://medium.com/@odarbelaeze/how-competitive-are-c-standard-random-number-generators-f3de98d973f0
  // thread_local is used on the basis of https://stackoverflow.com/questions/40655814/is-mersenne-twister-thread-safe-for-cpp
  thread_local std::random_device rd;  // Will be used to obtain a seed for the random number engine
  thread_local std::mt19937_64 gen(rd()); // Standard 64-bit mersenne_twister_engine seeded with rd()
  std::uniform_real_distribution<double> uni_dis(0, 1.0);

  // set the very first element
  array[0].ip4_suffix = suffix_min = 1;
  array[0].psid = psid_min = 0;
  
  for ( index=1; index<size; index++ ){
    // prepare the coordinates
    x = index / ysize;	// suffix field relative to suffix_min
    y = index % ysize;	// psid field relative to psid_min
    suffix_field = x + suffix_min;	// real suffix field
    psid_field = y + psid_min;	// real psid field
    // generate a random integer in the range [0, index] using uni_dis(gen), a random double in [0, 1).
    random = uni_dis(gen)*(index+1);

    // condition "if ( random != index )" is left out to spare a branch instruction on the cost of a redundant copy
    array[index].ip4_suffix = array[random].ip4_suffix;
    array[index].psid = array[random].psid;
    array[random].ip4_suffix = suffix_field;
    array[random].psid = psid_field;
      
  }

}

// creates an array of unique pseudorandom EA combinations
int randomPermutationGenerator48(void *par) {
  // collecting input parameters:
  class randomPermutationGeneratorParameters48 *p = (class randomPermutationGeneratorParameters48 *)par;
  uint8_t ip4_suffix_length = p->ip4_suffix_length;
  uint8_t psid_length = p->psid_length;
  uint64_t hz = p->hz;		// just for giving info about execution time
  const char *direction = p->direction;
  uint64_t start_gen, end_gen;  // timestamps for the above purpose 
  EAbits48 *array= NULL;	// array for storing the unique EA combinations
  uint64_t size = (pow(2.0,ip4_suffix_length)-2)*(pow(2.0,psid_length));  // size of the above array;

  array = (EAbits48 *) rte_malloc("Pre-generated unique EA 48-bits combinations", (sizeof(EAbits48))*size, 128);
  if ( !array )
    rte_exit(EXIT_FAILURE, "Error: Can't allocate NUMA local memory for Pre-generated unique EA-bits combinations array for the %s sender!\n", direction);
  
  std::cout << "Info: Pre-generating NUMA local unique EA-bits combinations for the " << direction << " sender\n";
  start_gen = rte_rdtsc();
  randomPermutation48(array,ip4_suffix_length,psid_length);
  end_gen = rte_rdtsc();
  std::cout << "Done. lasted " << 1.0*(end_gen-start_gen)/hz << " seconds for the " << direction << " sender\n";

  *(p->addr_of_arraypointer) = array;	// set the pointer in the caller
}

// creates an array of the simulated CE elements
int buildCEArray(void *par){
// collecting input parameters
  class CEArrayBuilderParameters *p = (class CEArrayBuilderParameters *)par;
  CE_data **addr_of_arraypointer= NULL;	
  EAbits48 *UniqueEAComb = p->UniqueEAComb;       
  uint8_t bmr_ipv4_suffix_length = p->bmr_ipv4_suffix_length; 
  uint8_t psid_length = p->psid_length;            
  uint32_t num_of_CEs = p->num_of_CEs;             
  struct in6_addr bmr_ipv6_prefix = p->bmr_ipv6_prefix; 
  uint8_t bmr_ipv6_prefix_length = p->bmr_ipv6_prefix_length;  
  uint32_t bmr_ipv4_prefix = p->bmr_ipv4_prefix;        
  uint64_t hz = p->hz; // just for giving info about execution time
  const char *direction = p->direction; 
  uint64_t start_gen, end_gen;  // timestamps for the above purpose 

  if (!UniqueEAComb)
    rte_exit(EXIT_FAILURE, "buildCEArray(): a NULL pointer to the array of pre-prepaired unique EA-bits combinations at the %s sender!\n", direction);
	// unique pseudorandom EA-bits pairs are supplied by the pre-prepaired random permutation
  
  // some local variables
  EAbits48 *uniqueEA = UniqueEAComb; // a working pointer to the current element of uniqueEAComb
  uint64_t uniqueEAsize = (pow(2.0,bmr_ipv4_suffix_length)-2)*(pow(2.0,psid_length)); // The size of the uniqueEAComb array (i.e., no. of elements)
  CE_data *CE = NULL;             // a pointer to the currently simulated CE's data.
  uint32_t bmr_ipv4_suffix;       // The pseudorandomly selected ipv4 suffix for the simulated CE
  uint64_t end_user_ipv6_prefix = 0; // The leftmost part of the MAP address
  uint64_t interface_id = 0;       // The rightmost part of the MAP address
  uint32_t map_addr_chksum = 0;   // The checksum of the MAP address to be added later to the UDP checksum of the sent packet
  uint8_t bmr_ipv6_prefix_bytes;  // The number of bytes allocated to the bmr_ipv6_prefix in the map address
  uint8_t bmr_ipv6_prefix_bits;   // The number of bits in the last byte fragment needed to complete the bmr_ipv6_prefix in the map address

  bmr_ipv6_prefix_bytes = bmr_ipv6_prefix_length / 8;
  bmr_ipv6_prefix_bits = bmr_ipv6_prefix_length % 8;

  CE = (CE_data *)rte_malloc("CEs data memory", num_of_CEs * sizeof(CE_data), 0);
  if (!CE)
    rte_exit(EXIT_FAILURE, "malloc failure!! Can not allocate memory for CEs data at the %s sender!\n", direction);

  start_gen = rte_rdtsc();
  for (int curr = 0; curr < num_of_CEs; curr++)
  {
    // resetting checksums
    CE[curr].ipv4_addr_chksum = 0;
    CE[curr].map_addr_chksum = 0;

    // Assign the current pseudorandomly enumerated EA fields 
    bmr_ipv4_suffix = uniqueEA->ip4_suffix;
    CE[curr].psid = uniqueEA->psid;

    // step to the next EA combination
    uniqueEA++;

    // Generating the map address
    for (int i = 0; i < bmr_ipv6_prefix_bytes; i++)
      end_user_ipv6_prefix = (end_user_ipv6_prefix << 8) | bmr_ipv6_prefix.s6_addr[i];
   
    if (bmr_ipv6_prefix_bits)
      end_user_ipv6_prefix = (end_user_ipv6_prefix << bmr_ipv6_prefix_bits) | (bmr_ipv6_prefix.s6_addr[bmr_ipv6_prefix_bytes] >> (8 - bmr_ipv6_prefix_bits));
   
    end_user_ipv6_prefix = (end_user_ipv6_prefix << bmr_ipv4_suffix_length) | bmr_ipv4_suffix;
    end_user_ipv6_prefix = (end_user_ipv6_prefix << psid_length) | CE[curr].psid;
    CE[curr].ipv4_addr = bmr_ipv4_prefix | htonl(bmr_ipv4_suffix);
    CE[curr].ipv4_addr_chksum = rte_raw_cksum(&CE[curr].ipv4_addr, 4); //calculate the IPv4 header checksum
    interface_id = interface_id | ntohl(CE[curr].ipv4_addr);
    interface_id = interface_id << 16 | CE[curr].psid;
    CE[curr].map_addr = concatenate(end_user_ipv6_prefix, interface_id);
    
    for (int j = 0; j < 16; j = j + 2) // calculate the MAP address checksum that will be added to the UDP checksum later
      map_addr_chksum += ((CE[curr].map_addr.s6_addr[j + 1] & 0x00ff) << 8) | CE[curr].map_addr.s6_addr[j];

    map_addr_chksum = ((map_addr_chksum & 0xffff0000) >> 16) + (map_addr_chksum & 0xffff); // add any carry to the final result
    map_addr_chksum = ((map_addr_chksum & 0xffff0000) >> 16) + (map_addr_chksum & 0xffff); // Twice is enough
    CE[curr].map_addr_chksum = map_addr_chksum;

    // reset some variables for the next cycle
    end_user_ipv6_prefix = 0;
    interface_id = 0;
    map_addr_chksum = 0;
  }
  
   end_gen = rte_rdtsc();
    std::cout << "Info: building CE Array: Done. lasted " << 1.0*(end_gen-start_gen)/hz << " seconds for the " << direction << " sender\n";
  *(p->addr_of_arraypointer) = CE;	// set the pointer in the caller
}


