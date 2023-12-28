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

int main(int argc, const char **argv)
{
  class Pdv tester;

  if (tester.readConfigFile(CONFIGFILE) < 0)
    return -1;
  if (tester.readCmdLine(argc, argv) < 0)
    return -1;
  if (tester.init(argv[0], LEFTPORT, RIGHTPORT) < 0)
    return -1;
  tester.measure(LEFTPORT, RIGHTPORT);
}
