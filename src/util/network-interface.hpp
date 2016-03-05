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

#ifndef NDN_UTIL_NETWORK_INTERFACE_HPP
#define NDN_UTIL_NETWORK_INTERFACE_HPP

#include "ethernet.hpp"
#include "network-monitor.hpp"
#include "signal.hpp"

#include <boost/asio/ip/address.hpp>

#include <set>

namespace ndn {
namespace util {

/** @brief Indicates the state of a network interface
 */
enum class NetworkInterfaceState {
  UNKNOWN,    ///< interface is in an unknown state
  DOWN,       ///< interface is administratively down
  NO_CARRIER, ///< interface is administratively up but has no carrier
  DORMANT,    ///< interface has a carrier but it cannot send or receive normal user traffic yet
  RUNNING     ///< interface can be used to send and receive packets
};

std::ostream&
operator<<(std::ostream& os, NetworkInterfaceState state);


/** @brief Represents a system network interface, exposes several link- and network-layer
 *         information, and emits specific signals when each information changes
 */
class NetworkInterface
{
public: // signals
  /** @brief Fires when interface name changes
   */
  Signal<NetworkInterface, std::string/*old*/, std::string/*new*/> onNameChanged;

  /** @brief Fires when interface state changes
   */
  Signal<NetworkInterface, NetworkInterfaceState/*old*/, NetworkInterfaceState/*new*/> onStateChanged;

  /** @brief Fires when interface mtu changes
   */
  Signal<NetworkInterface, uint32_t/*old*/, uint32_t/*new*/> onMtuChanged;

  /** @brief Fires when an IP address is added to the interface
   */
  Signal<NetworkInterface, boost::asio::ip::address> onAddressAdded;

  /** @brief Fires when an address is removed from the interface
   */
  Signal<NetworkInterface, boost::asio::ip::address> onAddressRemoved;

public: // getters
  int
  getIndex() const
  {
    return m_index;
  }

  std::string
  getName() const
  {
    return m_name;
  }

  unsigned int
  getFlags() const
  {
    return m_flags;
  }

  NetworkInterfaceState
  getState() const
  {
    return m_state;
  }

  uint32_t
  getMtu() const
  {
    return m_mtu;
  }

  ethernet::Address
  getEthernetAddress() const
  {
    return m_etherAddress;
  }

  ethernet::Address
  getEthernetBroadcastAddress() const
  {
    return m_etherBrdAddress;
  }

  const std::set<boost::asio::ip::address_v4>&
  getIpv4Addresses() const
  {
    return m_ipv4Addresses;
  }

  boost::asio::ip::address_v4
  getIpv4BroadcastAddress() const
  {
    return m_ipv4BrdAddress;
  }

  const std::set<boost::asio::ip::address_v6>&
  getIpv6Addresses() const
  {
    return m_ipv6Addresses;
  }

  /** @brief Returns true if the interface is a loopback interface
   */
  bool
  isLoopback() const
  {
    return (m_flags & IFF_LOOPBACK) != 0;
  }

  /** @brief Returns true if the interface supports broadcast communication
   */
  bool
  isBroadcastCapable() const
  {
    return (m_flags & IFF_BROADCAST) != 0;
  }

  /** @brief Returns true if the interface supports multicast communication
   */
  bool
  isMulticastCapable() const
  {
    return (m_flags & IFF_MULTICAST) != 0;
  }

  /** @brief Returns true if the interface is administratively up
   */
  bool
  isUp() const
  {
    return (m_flags & IFF_UP) != 0;
  }

private: // constructor
  explicit
  NetworkInterface(int index);

private: // modifiers
  void
  addIpAddress(const boost::asio::ip::address& address);

  void
  removeIpAddress(const boost::asio::ip::address& address);

  void
  setName(std::string name);

  void
  setFlags(unsigned int flags);

  void
  setState(NetworkInterfaceState state);

  void
  setMtu(uint32_t mtu);

  void
  setEthernetAddress(const ethernet::Address& address);

  void
  setEthernetBroadcastAddress(const ethernet::Address& address);

  void
  setIpv4BroadcastAddress(const boost::asio::ip::address_v4& address);

private:
  friend class NetworkMonitor::Impl;

  int m_index;
  std::string m_name;
  unsigned int m_flags;
  NetworkInterfaceState m_state;
  uint32_t m_mtu;
  ethernet::Address m_etherAddress;
  ethernet::Address m_etherBrdAddress;
  std::set<boost::asio::ip::address_v4> m_ipv4Addresses;
  boost::asio::ip::address_v4 m_ipv4BrdAddress;
  std::set<boost::asio::ip::address_v6> m_ipv6Addresses;
};

std::ostream&
operator<<(std::ostream& os, const NetworkInterface& interface);

} // namespace util
} // namespace ndn

#endif // NDN_UTIL_NETWORK_INTERFACE_HPP
