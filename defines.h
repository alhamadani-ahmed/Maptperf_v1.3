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

#define CONFIGFILE "maptperf.conf" /* name of the configuration file */
#define LINELEN 100                /* max. line length, used by config file reader */
#define LEFTPORT 0                 /* port ID of the "Left" port */
#define RIGHTPORT 1                /* port ID of the "Right" port */
#define MAX_PORT_TRIALS 10         /* rte_eth_link_get() is attempted maximum so many times, and error is reported if still unsuccessful */
#define START_DELAY 5000           /* Delay (ms) before senders start sending, used for synchronized start. Beware that DUT NICs need time to get ready! */
#define TOLERANCE 1.00001          /* Maximum allowed time inaccuracy, 1.00001 allows 0.001% more time for sending */
#define N 40                       /* used for PDV and varport: all frames exist in N copies to mitigate the problem of write after send */

//#define WIDE_DPORT_MIN 1     // default value: use maximum range recommended by RFC 4814
//#define WIDE_DPORT_MAX 49151 // default value: use maximum range recommended by RFC 4814
//#define WIDE_SPORT_MIN 1024  // default value: use maximum range recommended by RFC 4814
//#define WIDE_SPORT_MAX 65535 // default value: use maximum range recommended by RFC 4814

// values taken from DPDK sample programs
#define MAX_PKT_BURST 32 /* Maximum burst size for rte_eth_rx_burst() */
#define PKTPOOL_CACHE 32 /* used by rte_pktmbuf_pool_create() */
#define PORT_RX_QUEUE_SIZE 1024
#define PORT_TX_QUEUE_SIZE 1024