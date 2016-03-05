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

#include "network-interface.hpp"
#include "linux-if-constants.hpp"

#include <net/if.h>

namespace ndn {
namespace util {

NetworkInterface::NetworkInterface(int index)
  : m_index(index)
  , m_flags(0)
  , m_state(NetworkInterfaceState::UNKNOWN)
  , m_mtu(0)
{
  BOOST_ASSERT(m_index > 0);
}

void
NetworkInterface::addIpAddress(const boost::asio::ip::address& address)
{
  bool didInsert = false;

  if (address.is_v4())
    didInsert = m_ipv4Addresses.insert(address.to_v4()).second;
  else
    didInsert = m_ipv6Addresses.insert(address.to_v6()).second;

  if (didInsert)
    onAddressAdded(address);
}

void
NetworkInterface::removeIpAddress(const boost::asio::ip::address& address)
{
  bool didErase = false;

  if (address.is_v4())
    didErase = m_ipv4Addresses.erase(address.to_v4()) > 0;
  else
    didErase = m_ipv6Addresses.erase(address.to_v6()) > 0;

  if (didErase)
    onAddressRemoved(address);
}

void
NetworkInterface::setName(std::string name)
{
  BOOST_ASSERT(!name.empty());

  if (m_name != name) {
    std::swap(m_name, name);
    onNameChanged(name, m_name);
  }
}

void
NetworkInterface::setFlags(unsigned int flags)
{
  m_flags = flags;
}

void
NetworkInterface::setState(NetworkInterfaceState state)
{
  if (m_state != state) {
    std::swap(m_state, state);
    onStateChanged(state, m_state);
  }
}

void
NetworkInterface::setMtu(uint32_t mtu)
{
  if (m_mtu != mtu) {
    std::swap(m_mtu, mtu);
    onMtuChanged(mtu, m_mtu);
  }
}

void
NetworkInterface::setEthernetAddress(const ethernet::Address& address)
{
  m_etherAddress = address;
}

void
NetworkInterface::setEthernetBroadcastAddress(const ethernet::Address& address)
{
  m_etherBrdAddress = address;
}

void
NetworkInterface::setIpv4BroadcastAddress(const boost::asio::ip::address_v4& address)
{
  m_ipv4BrdAddress = address;
}

static void
printFlag(std::ostream& os, unsigned int& flags, unsigned int flagVal, const char* flagStr)
{
  if (flags & flagVal) {
    flags &= ~flagVal;
    os << flagStr << (flags ? "," : "");
  }
}

std::ostream&
operator<<(std::ostream& os, const NetworkInterface& netif)
{
  os << netif.getIndex() << ": " << netif.getName() << ": ";

  auto flags = netif.getFlags();
  os << "<";
#define PRINT_IFF(flag) printFlag(os, flags, IFF_##flag, #flag)
  PRINT_IFF(UP);
  PRINT_IFF(DEBUG);
  PRINT_IFF(LOOPBACK);
  PRINT_IFF(POINTOPOINT);
  PRINT_IFF(BROADCAST);
  PRINT_IFF(MULTICAST);
  PRINT_IFF(NOTRAILERS);
  PRINT_IFF(RUNNING);
  PRINT_IFF(NOARP);
  PRINT_IFF(PROMISC);
  PRINT_IFF(ALLMULTI);
#if defined(__linux__)
  PRINT_IFF(MASTER);
  PRINT_IFF(SLAVE);
  PRINT_IFF(PORTSEL);
  PRINT_IFF(AUTOMEDIA);
  PRINT_IFF(DYNAMIC);
#elif defined(__APPLE__) || defined(__FreeBSD__)
  PRINT_IFF(OACTIVE);
  PRINT_IFF(SIMPLEX);
  PRINT_IFF(ALTPHYS);
#endif
#undef PRINT_IFF
#if defined(__linux__)
#define PRINT_IF_FLAG(flag) printFlag(os, flags, linux_if::FLAG_##flag, #flag)
  PRINT_IF_FLAG(LOWER_UP);
  PRINT_IF_FLAG(DORMANT);
  PRINT_IF_FLAG(ECHO);
#undef PRINT_IF_FLAG
#endif
  if (flags) {
    // print unknown flags in hex
    auto saved = os.flags();
    os << std::hex << std::showbase << flags;
    os.flags(saved);
  }
  os << ">";

  os << " state " << netif.getState() << " mtu " << netif.getMtu() << "\n";

  if (!netif.isLoopback())
    os << "    ether " << netif.getEthernetAddress()
       << " brd " << netif.getEthernetBroadcastAddress() << "\n";

  for (const auto& addr : netif.getIpv4Addresses())
    os << "    inet " << addr << "\n";

  if (netif.isBroadcastCapable() && !netif.getIpv4BroadcastAddress().is_unspecified())
    os << "    inet brd " << netif.getIpv4BroadcastAddress() << "\n";

  for (const auto& addr : netif.getIpv6Addresses())
    os << "    inet6 " << addr << "\n";

  return os;
}

std::ostream&
operator<<(std::ostream& os, NetworkInterfaceState state)
{
  switch (state) {
    case NetworkInterfaceState::UNKNOWN:
      return os << "unknown";
    case NetworkInterfaceState::DOWN:
      return os << "down";
    case NetworkInterfaceState::NO_CARRIER:
      return os << "no-carrier";
    case NetworkInterfaceState::DORMANT:
      return os << "dormant";
    case NetworkInterfaceState::RUNNING:
      return os << "running";
    default:
      return os << static_cast<unsigned>(state);
  }
}

} // namespace util
} // namespace ndn
