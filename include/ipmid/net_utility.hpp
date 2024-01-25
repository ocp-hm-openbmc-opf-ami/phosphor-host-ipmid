/**
 * Copyright © 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once
#include <arpa/inet.h>
#include <string>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

namespace ipmi
{
namespace utility
{


namespace ip_address {
enum class Type {
    GATEWAY4_ADDRESS,
    GATEWAY6_ADDRESS,
    IP4_ADDRESS,
    IP6_ADDRESS
};

bool in6AddrIetfProtocolAssignment(in6_addr* addr);

bool in6AddrDoc(in6_addr* addr);

bool isValidIPv4Addr(in_addr* addr, Type type);

bool isValidIPv6Addr(in6_addr* addr, Type type);

} // namespace ip_address

} // namespace utility

} // namespace ipmi
