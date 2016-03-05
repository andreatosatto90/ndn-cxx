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
 *
 *
 * Parts of this implementation is based on daemondo command of MacPorts
 * (https://www.macports.org/):
 *
 *    Copyright (c) 2005-2007 James Berry <jberry@macports.org>
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the name of The MacPorts Project nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *   POSSIBILITY OF SUCH DAMAGE.
 */

#include "ndn-cxx-config.hpp"

#include "network-monitor.hpp"
#include "network-interface.hpp"

#if defined(NDN_CXX_HAVE_COREFOUNDATION_COREFOUNDATION_H)

#include "scheduler.hpp"
#include "scheduler-scoped-event-id.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

namespace ndn {
namespace util {

class NetworkMonitor::Impl
{
public:
  Impl(boost::asio::io_service& io)
    : scheduler(io)
    , cfLoopEvent(scheduler)
  {
  }

  void
  scheduleCfLoop()
  {
    // poll each second for new events
    cfLoopEvent = scheduler.scheduleEvent(time::seconds(1), bind(&Impl::pollCfLoop, this));
  }

  static void
  afterNotificationCenterEvent(CFNotificationCenterRef center, void *observer, CFStringRef name,
                               const void *object, CFDictionaryRef userInfo)
  {
    static_cast<NetworkMonitor*>(observer)->onNetworkStateChanged();
  }

private:
  void
  pollCfLoop()
  {
    // this should dispatch ready events and exit
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
    scheduleCfLoop();
  }

private:
  Scheduler scheduler;
  scheduler::ScopedEventId cfLoopEvent;
};

NetworkMonitor::NetworkMonitor(boost::asio::io_service& io)
  : m_impl(new Impl(io))
{
  m_impl->scheduleCfLoop();

  // Potentially useful System Configuration regex patterns:
  //
  // State:/Network/Interface/.*/Link
  // State:/Network/Interface/.*/IPv4
  // State:/Network/Interface/.*/IPv6
  //
  // State:/Network/Global/DNS
  // State:/Network/Global/IPv4
  //
  // Potentially useful notifications from Darwin Notify Center:
  //
  // com.apple.system.config.network_change

  // network change observations
  CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                  static_cast<void*>(this),
                                  &NetworkMonitor::Impl::afterNotificationCenterEvent,
                                  CFSTR("com.apple.system.config.network_change"),
                                  nullptr, // object to observe
                                  CFNotificationSuspensionBehaviorDeliverImmediately);
}

NetworkMonitor::~NetworkMonitor()
{
  CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                          static_cast<void*>(this));
}

} // namespace util
} // namespace ndn

// done with defined(NDN_CXX_HAVE_COREFOUNDATION_COREFOUNDATION_H)
#elif defined(NDN_CXX_HAVE_RTNETLINK)

#include "linux-if-constants.hpp"

#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/write.hpp>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>

namespace ndn {
namespace util {

class NetworkMonitor::Impl
{
public:
  /** \brief initialize netlink socket and start enumerating interfaces
   */
  Impl(NetworkMonitor& nm, boost::asio::io_service& io);

private:
  struct RtnlRequest
  {
    nlmsghdr hdr;
    rtgenmsg msg;
  };

  bool
  isEnumerating() const;

  void
  initSocket();

  void
  sendDumpRequest(uint16_t nlmsgType);

  void
  onReceiveRtnl(const boost::system::error_code& error, size_t nBytesReceived);

  void
  parseLinkMessage(const nlmsghdr* nlh, const ifinfomsg* ifi);

  void
  parseAddressMessage(const nlmsghdr* nlh, const ifaddrmsg* ifa);

  static void
  updateInterfaceState(const shared_ptr<NetworkInterface>& interface, uint8_t operState);

private:
  NetworkMonitor& m_nm;

  std::array<uint8_t, 4096> m_buffer; ///< holds netlink messages received from the kernel
  boost::asio::posix::stream_descriptor m_socket; ///< the netlink socket
  uint32_t m_pid; ///< our port ID (unicast address for netlink sockets)
  uint32_t m_sequenceNo; ///< sequence number of the last netlink request sent to the kernel
  bool m_isEnumeratingLinks; ///< true if a dump of all links is in progress
  bool m_isEnumeratingAddresses; ///< true if a dump of all addresses is in progress
};

NetworkMonitor::Impl::Impl(NetworkMonitor& nm, boost::asio::io_service& io)
  : m_nm(nm)
  , m_socket(io)
  , m_pid(0)
  , m_sequenceNo(0)
  , m_isEnumeratingLinks(false)
  , m_isEnumeratingAddresses(false)
{
  initSocket();
  m_socket.async_read_some(boost::asio::buffer(m_buffer),
                           bind(&Impl::onReceiveRtnl, this, _1, _2));

  sendDumpRequest(RTM_GETLINK);
  m_isEnumeratingLinks = true;
}

bool
NetworkMonitor::Impl::isEnumerating() const
{
  return m_isEnumeratingLinks || m_isEnumeratingAddresses;
}

void
NetworkMonitor::Impl::initSocket()
{
  int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0)
    BOOST_THROW_EXCEPTION(Error(std::string("Cannot create netlink socket (") +
                                std::strerror(errno) + ")"));

  m_socket.assign(fd);

  sockaddr_nl addr{};
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = RTMGRP_LINK | RTMGRP_NOTIFY |
                   RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
                   RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1)
    BOOST_THROW_EXCEPTION(Error(std::string("Cannot bind netlink socket (") +
                                std::strerror(errno) + ")"));

  // find out what pid has been assigned to us
  socklen_t len = sizeof(addr);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
    m_pid = addr.nl_pid;
  else
    BOOST_THROW_EXCEPTION(Error(std::string("Cannot obtain netlink socket address (") +
                                std::strerror(errno) + ")"));
}

void
NetworkMonitor::Impl::sendDumpRequest(uint16_t nlmsgType)
{
  auto request = make_shared<RtnlRequest>();
  request->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request->msg));
  request->hdr.nlmsg_type = nlmsgType;
  request->hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request->hdr.nlmsg_seq = ++m_sequenceNo;
  request->hdr.nlmsg_pid = m_pid;
  request->msg.rtgen_family = AF_UNSPEC;

  boost::asio::async_write(m_socket, boost::asio::buffer(request.get(), sizeof(RtnlRequest)),
    // capture 'request' to prevent its premature deallocation
    [request] (const boost::system::error_code& error, size_t) {
      if (error) {
        BOOST_THROW_EXCEPTION(
          Error(std::string("Failed to send netlink request (") + error.message() + ")"));
      }
    });
}

void
NetworkMonitor::Impl::onReceiveRtnl(const boost::system::error_code& error, size_t nBytesReceived)
{
  if (error) {
    BOOST_THROW_EXCEPTION(
      Error(std::string("Netlink socket read failed (") + error.message() + ")"));
  }

  const nlmsghdr* nlh = reinterpret_cast<const nlmsghdr*>(m_buffer.data());
  while (NLMSG_OK(nlh, nBytesReceived) && nlh->nlmsg_type != NLMSG_DONE) {
    switch (nlh->nlmsg_type) {

    case RTM_NEWLINK:
    case RTM_DELLINK:
      parseLinkMessage(nlh, reinterpret_cast<const ifinfomsg*>(NLMSG_DATA(nlh)));
      if (!isEnumerating())
        m_nm.onNetworkStateChanged(); // backward compat
      break;

    case RTM_NEWADDR:
    case RTM_DELADDR:
      parseAddressMessage(nlh, reinterpret_cast<const ifaddrmsg*>(NLMSG_DATA(nlh)));
      if (!isEnumerating())
        m_nm.onNetworkStateChanged(); // backward compat
      break;

    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      // TODO: handle routes
      if (!isEnumerating())
        m_nm.onNetworkStateChanged(); // backward compat
      break;

    case NLMSG_ERROR:
      // TODO: what do we do with errors here? throwing seems a bit too drastic
      // const nlmsgerr* err = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(nlh));
      // BOOST_THROW_EXCEPTION(Error(std::strerror(err->error)));
      break;
    }

    nlh = NLMSG_NEXT(nlh, nBytesReceived);
  }

  if (nlh->nlmsg_type == NLMSG_DONE &&
      nlh->nlmsg_seq == m_sequenceNo &&
      nlh->nlmsg_pid == m_pid) {
    if (m_isEnumeratingLinks) {
      // links enumeration complete, now request all the addresses
      m_isEnumeratingLinks = false;
      sendDumpRequest(RTM_GETADDR);
      m_isEnumeratingAddresses = true;
    }
    else if (m_isEnumeratingAddresses) {
      // links and addresses enumeration complete
      m_isEnumeratingAddresses = false;
      m_nm.onEnumerationCompleted();
    }
  }

  m_socket.async_read_some(boost::asio::buffer(m_buffer),
                           bind(&Impl::onReceiveRtnl, this, _1, _2));
}

void
NetworkMonitor::Impl::parseLinkMessage(const nlmsghdr* nlh, const ifinfomsg* ifi)
{
  if (ifi->ifi_type != ARPHRD_ETHER && ifi->ifi_type != ARPHRD_LOOPBACK) {
    // we do not support anything else
    return;
  }

  shared_ptr<NetworkInterface> interface;
  auto it = m_nm.m_networkInterfaces.find(ifi->ifi_index);
  if (it != m_nm.m_networkInterfaces.end()) {
    interface = it->second;
  }

  if (nlh->nlmsg_type == RTM_DELLINK) {
    if (interface != nullptr) {
      m_nm.m_networkInterfaces.erase(it);
      m_nm.onInterfaceRemoved(interface);
    }
    return;
  }

  if (interface == nullptr) {
    // cannot use make_shared because NetworkInterface constructor is private
    interface.reset(new NetworkInterface(ifi->ifi_index));
  }
  interface->setFlags(ifi->ifi_flags);

  const rtattr* rta = reinterpret_cast<const rtattr*>(IFLA_RTA(ifi));
  size_t rtaTotalLen = IFLA_PAYLOAD(nlh);
  uint8_t operState = linux_if::OPER_STATE_UNKNOWN;

  while (RTA_OK(rta, rtaTotalLen)) {
    size_t attrLen = RTA_PAYLOAD(rta);

    switch (rta->rta_type) {
      case IFLA_ADDRESS:
        if (attrLen == ethernet::ADDR_LEN) {
          ethernet::Address addr(reinterpret_cast<const unsigned char*>(RTA_DATA(rta)));
          interface->setEthernetAddress(addr);
        }
        break;

      case IFLA_BROADCAST:
        if (attrLen == ethernet::ADDR_LEN) {
          ethernet::Address addr(reinterpret_cast<const unsigned char*>(RTA_DATA(rta)));
          interface->setEthernetBroadcastAddress(addr);
        }
        break;

      case IFLA_IFNAME: {
        auto attrData = reinterpret_cast<const char*>(RTA_DATA(rta));
        if (::strnlen(attrData, attrLen) <= attrLen)
          interface->setName(attrData);
        break;
      }

      case IFLA_MTU:
        if (attrLen == sizeof(uint32_t))
          interface->setMtu(*(reinterpret_cast<const uint32_t*>(RTA_DATA(rta))));
        break;

      case IFLA_OPERSTATE:
        if (attrLen == sizeof(uint8_t))
          operState = *(reinterpret_cast<const uint8_t*>RTA_DATA(rta));
        break;
    }

    rta = RTA_NEXT(rta, rtaTotalLen);
  }

  updateInterfaceState(interface, operState);

  if (it == m_nm.m_networkInterfaces.end()) {
    // new interface
    m_nm.m_networkInterfaces[ifi->ifi_index] = interface;
    m_nm.onInterfaceAdded(interface);
  }
}

void
NetworkMonitor::Impl::parseAddressMessage(const nlmsghdr* nlh, const ifaddrmsg* ifa)
{
  namespace ip = boost::asio::ip;

  auto it = m_nm.m_networkInterfaces.find(ifa->ifa_index);
  if (it == m_nm.m_networkInterfaces.end()) {
    // unknown interface, ignore message
    return;
  }

  auto interface = it->second;
  BOOST_ASSERT(interface != nullptr);

  const rtattr* rta = reinterpret_cast<const rtattr*>(IFA_RTA(ifa));
  size_t rtaTotalLen = IFA_PAYLOAD(nlh);

  while (RTA_OK(rta, rtaTotalLen)) {
    auto attrData = reinterpret_cast<const unsigned char*>(RTA_DATA(rta));
    size_t attrLen = RTA_PAYLOAD(rta);

    switch (rta->rta_type) {
      case IFA_LOCAL:
        if (ifa->ifa_family == AF_INET && attrLen == sizeof(ip::address_v4::bytes_type)) {
          ip::address_v4::bytes_type bytes;
          std::copy_n(attrData, bytes.size(), bytes.begin());
          ip::address_v4 address(bytes);

          if (!address.is_unspecified()) {
            if (nlh->nlmsg_type == RTM_NEWADDR)
              interface->addIpAddress(address);
            else if (nlh->nlmsg_type == RTM_DELADDR)
              interface->removeIpAddress(address);
          }
        }
        break;

      case IFA_ADDRESS:
        if (ifa->ifa_family == AF_INET6 && attrLen == sizeof(ip::address_v6::bytes_type)) {
          ip::address_v6::bytes_type bytes;
          std::copy_n(attrData, bytes.size(), bytes.begin());
          ip::address_v6 address(bytes);

          if (!address.is_unspecified()) {
            if (nlh->nlmsg_type == RTM_NEWADDR)
              interface->addIpAddress(address);
            else if (nlh->nlmsg_type == RTM_DELADDR)
              interface->removeIpAddress(address);
          }
        }
        break;

      case IFA_BROADCAST:
        if (ifa->ifa_family == AF_INET && attrLen == sizeof(ip::address_v4::bytes_type)) {
          ip::address_v4::bytes_type bytes;
          std::copy_n(attrData, bytes.size(), bytes.begin());
          ip::address_v4 address(bytes);

          interface->setIpv4BroadcastAddress(address);
        }
        break;
    }

    rta = RTA_NEXT(rta, rtaTotalLen);
  }
}

void
NetworkMonitor::Impl::updateInterfaceState(const shared_ptr<NetworkInterface>& interface,
                                           uint8_t operState)
{
  if (operState == linux_if::OPER_STATE_UP) {
    interface->setState(NetworkInterfaceState::RUNNING);
  } else if (operState == linux_if::OPER_STATE_DORMANT) {
    interface->setState(NetworkInterfaceState::DORMANT);
  } else {
    // fallback to flags
    auto flags = interface->getFlags();
    if ((flags & linux_if::FLAG_LOWER_UP) && !(flags & linux_if::FLAG_DORMANT))
      interface->setState(NetworkInterfaceState::RUNNING);
    else if (flags & IFF_UP)
      interface->setState(NetworkInterfaceState::NO_CARRIER);
    else
      interface->setState(NetworkInterfaceState::DOWN);
  }
}

NetworkMonitor::NetworkMonitor(boost::asio::io_service& io)
  : m_impl(new Impl(*this, io))
{
}

NetworkMonitor::~NetworkMonitor() = default;

} // namespace util
} // namespace ndn

// done with defined(NDN_CXX_HAVE_RTNETLINK)
#else // do not support network monitoring operations

namespace ndn {
namespace util {

class NetworkMonitor::Impl
{
};

NetworkMonitor::NetworkMonitor(boost::asio::io_service&)
{
  BOOST_THROW_EXCEPTION(Error("Network monitoring is not supported on this platform"));
}

NetworkMonitor::~NetworkMonitor() = default;

} // namespace util
} // namespace ndn

#endif

/* Common methods */

namespace ndn {
namespace util {

shared_ptr<NetworkInterface>
NetworkMonitor::getNetworkInterface(int interfaceIndex)
{
  auto it = m_networkInterfaces.find(interfaceIndex);
  if (it != m_networkInterfaces.end())
    return it->second;
  else
    return nullptr;
}

shared_ptr<NetworkInterface>
NetworkMonitor::getNetworkInterface(const std::string& interfaceName)
{
  auto it = std::find_if(m_networkInterfaces.begin(), m_networkInterfaces.end(),
    [&interfaceName] (std::pair<const int, shared_ptr<NetworkInterface>>& ni) {
      return ni.second->getName() == interfaceName;
    });
  if (it != m_networkInterfaces.end())
    return it->second;
  else
    return nullptr;
}

std::vector<shared_ptr<NetworkInterface>>
NetworkMonitor::listNetworkInterfaces()
{
  std::vector<shared_ptr<NetworkInterface>> v;
  v.reserve(m_networkInterfaces.size());

  for (const auto& elem : m_networkInterfaces) {
    v.push_back(elem.second);
  }

  return v;
}

} // namespace util
} // namespace ndn
