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

#define BOOST_TEST_MAIN 1
#define BOOST_TEST_DYN_LINK 1
#define BOOST_TEST_MODULE ndn-cxx Integrated Tests (Network Monitor)

#include "util/network-monitor.hpp"

#include "util/network-interface.hpp"
#include "util/time.hpp"

#include "boost-test.hpp"

#include <boost/asio/io_service.hpp>
#include <iostream>

namespace ndn {
namespace util {
namespace tests {

BOOST_AUTO_TEST_SUITE(Util)
BOOST_AUTO_TEST_SUITE(TestNetworkMonitor)

static std::ostream&
logEvent(const shared_ptr<NetworkInterface>& ni = nullptr, std::ostream& os = std::cout)
{
  os << time::toString(time::system_clock::now()) << '\t';
  if (ni != nullptr)
    os << "[" << ni->getName() << "] ";
  return os;
}

BOOST_AUTO_TEST_CASE(Signals)
{
  boost::asio::io_service io;
  NetworkMonitor monitor(io);

  monitor.onNetworkStateChanged.connect([] {
    logEvent() << "onNetworkStateChanged" << std::endl;
  });

  monitor.onEnumerationCompleted.connect([&monitor] {
    logEvent() << "onEnumerationCompleted" << std::endl;
    for (const auto& ni : monitor.listNetworkInterfaces()) {
      std::cout << *ni;
    }
  });

  monitor.onInterfaceAdded.connect([] (const shared_ptr<NetworkInterface>& ni) {
    logEvent(ni) << "onInterfaceAdded\n" << *ni;

    ni->onAddressAdded.connect([ni] (boost::asio::ip::address address) {
      logEvent(ni) << "onAddressAdded " << address << std::endl;
    });

    ni->onAddressRemoved.connect([ni] (boost::asio::ip::address address) {
      logEvent(ni) << "onAddressRemoved " << address << std::endl;
    });

    ni->onStateChanged.connect([ni] (NetworkInterfaceState oldState, NetworkInterfaceState newState) {
      logEvent(ni) << "onStateChanged " << oldState << " -> " << newState << std::endl;
    });

    ni->onMtuChanged.connect([ni] (uint32_t oldMtu, uint32_t newMtu) {
      logEvent(ni) << "onMtuChanged " << oldMtu << " -> " << newMtu << std::endl;
    });

    ni->onNameChanged.connect([ni] (std::string oldName, std::string newName) {
      logEvent(ni) << "onNameChanged " << oldName << " -> " << newName << std::endl;
    });
  }); // monitor.onInterfaceAdded.connect

  monitor.onInterfaceRemoved.connect([] (const shared_ptr<NetworkInterface>& ni) {
    logEvent(ni) << "onInterfaceRemoved" << std::endl;
  });

  io.run();
}

BOOST_AUTO_TEST_SUITE_END() // TestNetworkMonitor
BOOST_AUTO_TEST_SUITE_END() // Util

} // namespace tests
} // namespace util
} // namespace ndn
