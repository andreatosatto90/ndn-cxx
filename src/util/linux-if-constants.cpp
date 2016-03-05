/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2016 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "linux-if-constants.hpp"

#ifdef __linux__

#include <sys/socket.h>
#include <linux/if.h>

namespace ndn {
namespace util {
namespace linux_if {

const unsigned int FLAG_LOWER_UP = IFF_LOWER_UP;
const unsigned int FLAG_DORMANT  = IFF_DORMANT;
const unsigned int FLAG_ECHO     = IFF_ECHO;

const unsigned int OPER_STATE_UNKNOWN        = IF_OPER_UNKNOWN;
const unsigned int OPER_STATE_NOTPRESENT     = IF_OPER_NOTPRESENT;
const unsigned int OPER_STATE_DOWN           = IF_OPER_DOWN;
const unsigned int OPER_STATE_LOWERLAYERDOWN = IF_OPER_LOWERLAYERDOWN;
const unsigned int OPER_STATE_TESTING        = IF_OPER_TESTING;
const unsigned int OPER_STATE_DORMANT        = IF_OPER_DORMANT;
const unsigned int OPER_STATE_UP             = IF_OPER_UP;

} // namespace linux_if
} // namespace util
} // namespace ndn

#endif // __linux__
