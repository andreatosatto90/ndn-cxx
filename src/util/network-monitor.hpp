/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2016 Regents of the University of California.
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

#ifndef NDN_UTIL_NETWORK_MONITOR_HPP
#define NDN_UTIL_NETWORK_MONITOR_HPP

#include "signal.hpp"

#include <unordered_map>
#include <vector>

// forward declaration
namespace boost {
namespace asio {
class io_service;
} // namespace asio
} // namespace boost

namespace ndn {
namespace util {

class NetworkInterface;

/**
 * @brief Network interfaces monitor
 *
 * Maintains an up-to-date view of every system network interface and notifies when an interface
 * is added or removed.
 *
 * @note Implementation of this class is platform dependent and not all supported platforms
 *       are supported:
 *       - OS X: CFNotificationCenterAddObserver (incomplete)
 *       - Linux: rtnetlink notifications
 *
 * @todo OS X implementation needs to be updated with the new signals and interfaces bookkeeping
 */
class NetworkMonitor : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  /**
   * @brief Construct instance, request enumeration of all network interfaces, and start
   *        monitoring for network state changes
   *
   * @param io io_service thread that will dispatch events
   * @throw Error when network monitoring is not supported or there is an error starting monitoring
   */
  explicit
  NetworkMonitor(boost::asio::io_service& io);

  ~NetworkMonitor();

  shared_ptr<NetworkInterface>
  getNetworkInterface(int interfaceIndex);

  shared_ptr<NetworkInterface>
  getNetworkInterface(const std::string& interfaceName);

  std::vector<shared_ptr<NetworkInterface>>
  listNetworkInterfaces();

public: // signals
  /** @brief Fires when network interfaces enumeration is complete
   */
  Signal<NetworkMonitor> onEnumerationCompleted;

  /** @brief Fires when a new interface is added
   */
  Signal<NetworkMonitor, shared_ptr<NetworkInterface>> onInterfaceAdded;

  /**
   * @brief Fires when an interface is removed
   * @note The NetworkInterface object is no longer present in the network
   *       interfaces map when the signal is emitted
   */
  Signal<NetworkMonitor, shared_ptr<NetworkInterface>> onInterfaceRemoved;

  // only for backward compatibility
  Signal<NetworkMonitor> onNetworkStateChanged;

public:
  class Impl;
  friend class Impl; // needs to be friend to access m_networkInterfaces

private:
  std::unique_ptr<Impl> m_impl;
  std::unordered_map<int, shared_ptr<NetworkInterface>> m_networkInterfaces;
};

} // namespace util
} // namespace ndn

#endif // NDN_UTIL_NETWORK_MONITOR_HPP
