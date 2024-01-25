#include "ipmid/net_utility.hpp"

namespace ipmi
{
namespace utility
{
namespace ip_address {

using phosphor::logging::log;
using phosphor::logging::level;

bool in6AddrIetfProtocolAssignment(in6_addr* addr) {
    return (ntohl(addr->__in6_u.__u6_addr32[0]) >= 0x20010000 && ntohl(addr->__in6_u.__u6_addr32[0]) <= 0x200101ff);
}

bool in6AddrDoc(in6_addr* addr) {
    return ntohl(addr->__in6_u.__u6_addr32[0]) == 0x20010db8;
}

bool isValidIPv4Addr(in_addr* addr, Type type) {
    uint8_t ip[4];
    in_addr_t tmp = ntohl(addr->s_addr);
    for (int i = 0; i < 4; i++) {
        ip[i] = ( tmp >> (8 * (3 - i)) ) & 0xFF;
    } // for

    if (type == Type::GATEWAY4_ADDRESS) {
        if (ip[0] == 0) {
            log<level::INFO>("Gateway starts with 0.");
            return false;
        } // if
    } // if
    else if (type == Type::IP4_ADDRESS) {
        if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
            log<level::INFO>("Gateway starts with 0.");
            return false;
        } // if
    } // else if

    return true;
}


bool isValidIPv6Addr(in6_addr* addr, Type type) {
    std::string strType{"Gateway"};
    if (type == Type::IP6_ADDRESS) {
        strType = "IPv6";
        if(in6AddrIetfProtocolAssignment(addr)) {
            log<level::INFO>((strType+" address is IETF Protocol Assignments.").c_str());
            return false;
        }
        else if (in6AddrDoc(addr)) {
            log<level::INFO>((strType+" address is Documentation.").c_str());
            return false;
        }
        else if(IN6_IS_ADDR_LINKLOCAL(addr)) {
            log<level::INFO>((strType+" address is Link-local.").c_str());
            return false;
        }
    }

    if(IN6_IS_ADDR_LOOPBACK(addr)) {
        log<level::INFO>((strType+" address is Loopback.").c_str());
        return false;
    }
    else if(IN6_IS_ADDR_MULTICAST(addr)) {
        log<level::INFO>((strType+" address is Multicast.").c_str());
        return false;
    }
    else if (IN6_IS_ADDR_SITELOCAL(addr)) {
        log<level::INFO>((strType+" address is Sitelocal.").c_str());
        return false;
    }
    else if(IN6_IS_ADDR_V4MAPPED(addr)) {
        log<level::INFO>((strType+" address is V4Mapped.").c_str());
        return false;
    }
    else if(IN6_IS_ADDR_UNSPECIFIED(addr)) {
        log<level::INFO>((strType+" address is Unspecified.").c_str());
        return false;
    }

    return true;
}

} // namespace ip_address

} // namespace utility

} // namespace ipmi
