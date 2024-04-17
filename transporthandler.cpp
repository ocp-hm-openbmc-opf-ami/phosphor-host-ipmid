#include "transporthandler.hpp"

#include <stdplus/net/addr/subnet.hpp>
#include <stdplus/raw.hpp>

#include <array>
#include <fstream>

using phosphor::logging::commit;
using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::error::xyz::openbmc_project::common::InternalFailure;
using sdbusplus::error::xyz::openbmc_project::common::InvalidArgument;
using sdbusplus::server::xyz::openbmc_project::network::EthernetInterface;
using sdbusplus::server::xyz::openbmc_project::network::IP;
using sdbusplus::server::xyz::openbmc_project::network::Neighbor;
using sdbusplus::server::xyz::openbmc_project::network::ARPControl;

namespace cipher
{

std::vector<uint8_t> getCipherList()
{
    std::vector<uint8_t> cipherList;

    std::ifstream jsonFile(cipher::configFile);
    if (!jsonFile.is_open())
    {
        log<level::ERR>("Channel Cipher suites file not found");
        elog<InternalFailure>();
    }

    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        log<level::ERR>("Parsing channel cipher suites JSON failed");
        elog<InternalFailure>();
    }

    // Byte 1 is reserved
    cipherList.push_back(0x00);

    for (const auto& record : data)
    {
        cipherList.push_back(record.value(cipher, 0));
    }

    return cipherList;
}
} // namespace cipher

namespace ipmi
{
namespace transport
{

/** @brief Valid address origins for IPv4 */
const std::unordered_set<IP::AddressOrigin> originsV4 = {
    IP::AddressOrigin::Static,
    IP::AddressOrigin::DHCP,
};

static constexpr uint8_t oemCmdStart = 192;

// Checks if the ifname is part of the networkd path
// This assumes the path came from the network subtree PATH_ROOT
bool ifnameInPath(std::string_view ifname, std::string_view path)
{
    constexpr auto rs = PATH_ROOT.size() + 1; // ROOT + separator
    const auto is = rs + ifname.size();       // ROOT + sep + ifname
    return path.size() > rs && path.substr(rs).starts_with(ifname) &&
           (path.size() == is || path[is] == '/' || path[is] == '_');
}

std::optional<ChannelParams> maybeGetChannelParams(sdbusplus::bus_t& bus,
                                                   uint8_t channel)
{
    auto ifname = getChannelName(channel);
    if (ifname.empty())
    {
        return std::nullopt;
    }

    // Enumerate all VLAN + ETHERNET interfaces
    auto req = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ, MAPPER_INTF,
                                   "GetSubTree");
    req.append(std::string_view(PATH_ROOT), 0,
               std::vector<std::string>{INTF_VLAN, INTF_ETHERNET});
    auto reply = bus.call(req);
    ObjectTree objs;
    reply.read(objs);

    ChannelParams params;
    params.numIntfVlan = 0;
    params.numIntfEthernet = 0;
    for (const auto& [path, impls] : objs)
    {
        if (!ifnameInPath(ifname, path))
        {
            continue;
        }
        for (const auto& [service, intfs] : impls)
        {
            bool vlan = false;
            bool ethernet = false;
            for (const auto& intf : intfs)
            {
                if (intf == INTF_VLAN)
                {
                    vlan = true;
                    params.numIntfVlan += 1;
                }
                else if (intf == INTF_ETHERNET)
                {
                    ethernet = true;
                    params.numIntfEthernet += 1;
                }
            }
            if (params.service.empty() && (vlan || ethernet))
            {
                params.service = service;
            }
            if (params.ifPath.empty() && !vlan && ethernet)
            {
                params.ifPath = path;
            }
            if (params.logicalPath.empty() && vlan)
            {
                params.logicalPath = path;
            }
        }
    }

    // We must have a path for the underlying interface
    if (params.ifPath.empty())
    {
        return std::nullopt;
    }
    // We don't have a VLAN so the logical path is the same
    if (params.logicalPath.empty())
    {
        params.logicalPath = params.ifPath;
    }

    params.id = channel;
    params.ifname = std::move(ifname);
    return params;
}

ChannelParams getChannelParams(sdbusplus::bus_t& bus, uint8_t channel)
{
    auto params = maybeGetChannelParams(bus, channel);
    if (!params)
    {
        log<level::ERR>("Failed to get channel params",
                        entry("CHANNEL=%" PRIu8, channel));
        elog<InternalFailure>();
    }
    return std::move(*params);
}

/** @brief Wraps the phosphor logging method to insert some additional metadata
 *
 *  @param[in] params - The parameters for the channel
 *  ...
 */
template <auto level, typename... Args>
auto logWithChannel(const ChannelParams& params, Args&&... args)
{
    return log<level>(std::forward<Args>(args)...,
                      entry("CHANNEL=%d", params.id),
                      entry("IFNAME=%s", params.ifname.c_str()));
}
template <auto level, typename... Args>
auto logWithChannel(const std::optional<ChannelParams>& params, Args&&... args)
{
    if (params)
    {
        return logWithChannel<level>(*params, std::forward<Args>(args)...);
    }
    return log<level>(std::forward<Args>(args)...);
}

/** @brief Get / Set the Property value from phosphor-networkd EthernetInterface
 */
template <typename T>
static T getEthProp(sdbusplus::bus_t& bus, const ChannelParams& params,
                    const std::string& prop)
{
    return std::get<T>(getDbusProperty(bus, params.service, params.logicalPath,
                                       INTF_ETHERNET, prop));
}
template <typename T>
static void setEthProp(sdbusplus::bus_t& bus, const ChannelParams& params,
                       const std::string& prop, const T& t)
{
    return setDbusProperty(bus, params.service, params.logicalPath,
                           INTF_ETHERNET, prop, t);
}

/** @brief Determines the MAC of the ethernet interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return The configured mac address
 */
stdplus::EtherAddr getMACProperty(sdbusplus::bus_t& bus,
                                  const ChannelParams& params)
{
    auto prop = getDbusProperty(bus, params.service, params.ifPath, INTF_MAC,
                                "MACAddress");
    return stdplus::fromStr<stdplus::EtherAddr>(std::get<std::string>(prop));
}

/** @brief Sets the system value for MAC address on the given interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] mac    - MAC address to apply
 */
void setMACProperty(sdbusplus::bus_t& bus, const ChannelParams& params,
                    stdplus::EtherAddr mac)
{
    setDbusProperty(bus, params.service, params.ifPath, INTF_MAC, "MACAddress",
                    stdplus::toStr(mac));
}

void deleteObjectIfExists(sdbusplus::bus_t& bus, const std::string& service,
                          const std::string& path)
{
    if (path.empty())
    {
        return;
    }
    try
    {
        auto req = bus.new_method_call(service.c_str(), path.c_str(),
                                       ipmi::DELETE_INTERFACE, "Delete");
        bus.call_noreply(req);
    }
    catch (const sdbusplus::exception_t& e)
    {
        if (strcmp(e.name(),
                   "xyz.openbmc_project.Common.Error.InternalFailure") != 0 &&
            strcmp(e.name(), "org.freedesktop.DBus.Error.UnknownObject") != 0)
        {
            // We want to rethrow real errors
            throw;
        }
    }
}

/** @brief Sets the address info configured for the interface
 *         If a previous address path exists then it will be removed
 *         before the new address is added.
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] address - The address of the new IP
 *  @param[in] prefix  - The prefix of the new IP
 */
template <int family>
void createIfAddr(sdbusplus::bus_t& bus, const ChannelParams& params,
                  typename AddrFamily<family>::addr address, uint8_t prefix, uint8_t index = 0)
{
    auto newreq = bus.new_method_call(params.service.c_str(),
                                      params.logicalPath.c_str(),
                                      INTF_IP_CREATE, "IPWithIndex");
    std::string protocol =
        sdbusplus::common::xyz::openbmc_project::network::convertForMessage(
            AddrFamily<family>::protocol);
    stdplus::ToStrHandle<stdplus::ToStr<typename AddrFamily<family>::addr>> tsh;
    newreq.append(protocol, tsh(address), prefix, index,"");
    bus.call_noreply(newreq);
}

/** @brief Trivial helper for getting the IPv4 address from getIfAddrs()
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return The address and prefix if found
 */
auto getIfAddr4(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    return getIfAddr<AF_INET>(bus, params, 0, originsV4);
}

/** @brief Reconfigures the IPv4 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] address - The new address if specified
 *  @param[in] prefix  - The new address prefix if specified
 */
void reconfigureIfAddr4(sdbusplus::bus_t& bus, const ChannelParams& params,
                        std::optional<stdplus::In4Addr> address,
                        std::optional<uint8_t> prefix)
{
    auto ifaddr = getIfAddr4(bus, params);
    if (!ifaddr && !address)
    {
        log<level::ERR>("Missing address for IPv4 assignment");
        elog<InternalFailure>();
    }
    uint8_t fallbackPrefix = AddrFamily<AF_INET>::defaultPrefix;
    if (ifaddr)
    {
        fallbackPrefix = ifaddr->prefix;
        deleteObjectIfExists(bus, params.service, ifaddr->path);
    }

    createIfAddr<AF_INET>(bus, params, address.value_or(ifaddr->address), prefix.value_or(fallbackPrefix));
}

template <int family>
std::optional<IfNeigh<family>> findGatewayNeighbor(sdbusplus::bus_t& bus,
                                                   const ChannelParams& params,
                                                   ObjectLookupCache& neighbors)
{
    auto gateway = getGatewayProperty<family>(bus, params);
    if (!gateway)
    {
        return std::nullopt;
    }

    return findStaticNeighbor<family>(bus, params, *gateway, neighbors);
}

template <int family>
std::optional<IfNeigh<family>> getGatewayNeighbor(sdbusplus::bus_t& bus,
                                                  const ChannelParams& params)
{
    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    return findGatewayNeighbor<family>(bus, params, neighbors);
}

template <int family>
void reconfigureGatewayMAC(sdbusplus::bus_t& bus, const ChannelParams& params,
                           stdplus::EtherAddr mac)
{
    auto oldStaticAddr = getStaticRtrAddr<family>(bus, params);
    if (oldStaticAddr.empty())
    {
        log<level::ERR>("Tried to set Gateway MAC without Gateway");
        elog<InternalFailure>();
    }

    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    auto neighbor = findStaticNeighbor<family>(bus, params, stdplus::fromStr<stdplus::In6Addr>(oldStaticAddr),
                                               neighbors);
    auto prefixLength=neighbor->prefixLength;

    if (neighbor)
    {
        deleteObjectIfExists(bus, params.service, neighbor->path);
    }

    createNeighbor<family>(bus, params, stdplus::fromStr<stdplus::In6Addr>(oldStaticAddr), mac, prefixLength);
}


template <int family>
void reconfigureGatewayPrefixLength(sdbusplus::bus_t& bus, const ChannelParams& params,
                           const uint8_t prefixLength)
{
    auto oldStaticAddr = getStaticRtrAddr<family>(bus, params);
    if (oldStaticAddr.empty())
    {
        log<level::ERR>("Tried to set Gateway MAC without Gateway");
        elog<InternalFailure>();
    }

    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    auto neighbor =
        findStaticNeighbor<family>(bus, params, stdplus::fromStr<stdplus::In6Addr>(oldStaticAddr), neighbors);

    auto mac=neighbor->mac;

    if (neighbor)
    {
        deleteObjectIfExists(bus, params.service, neighbor->path);
    }

    createNeighbor<family>(bus, params, stdplus::fromStr<stdplus::In6Addr>(oldStaticAddr), mac, prefixLength);
}

/** @brief Gets the IPv6 Static Router value
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return networkd IPv6EnableStaticRtr value
 */
static bool getIPv6StaticRtr(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto enabled = std::get<bool>(getDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, "IPv6EnableStaticRtr"));
    return enabled;
}

template <int family>
std::string getStaticRtrAddr(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto addr = std::get<std::string>(getDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, "IPv6StaticRtrAddr"));
    return addr;
}

void setStaticRtrAddr(sdbusplus::bus_t& bus, const ChannelParams& params, in6_addr& address)
{
    // Save the old gateway MAC address if it exists so we can recreate it
    auto oldStaticAddr = getStaticRtrAddr<AF_INET6>(bus, params);
    std::optional<IfNeigh<AF_INET6>> neighbor;
    if (!oldStaticAddr.empty())
    {
        ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
        neighbor = findStaticNeighbor<AF_INET6>(bus, params, stdplus::fromStr<stdplus::In6Addr>(oldStaticAddr), neighbors);
        if (neighbor)
        {
            deleteObjectIfExists(bus, params.service, neighbor->path);
        }
    }

    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, "IPv6StaticRtrAddr", stdplus::toStr(stdplus::In6Addr{address}));
    createNeighbor<AF_INET6>(bus, params, address, stdplus::fromStr<stdplus::EtherAddr>("00:00:00:00:00:00"), AddrFamily<AF_INET6>::defaultPrefix);
}

template <int family>
std::optional<IfNeigh<family>> getStaticRtrNeighbor(sdbusplus::bus_t& bus, const ChannelParams& params) {
    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    auto routerAddr = getStaticRtrAddr<AF_INET6>(bus, params);
    if(routerAddr.empty()){
        return std::nullopt;
    }
    auto addr = stdplus::fromStr<stdplus::In6Addr>(routerAddr);
    return findStaticNeighbor<AF_INET6>(bus, params, addr, neighbors);
}

/** @brief Sets the IPv6EnableStaticRtr flag
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] enabled       - boolean to enable/disable IPv6 static router
 */
void setIPv6StaticRtr(sdbusplus::bus_t& bus, const ChannelParams& params,
                     const bool enabled)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET,
                    "IPv6EnableStaticRtr", enabled);
}

/** @brief Deletes Static Router Neighbor object
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 */
template <int family>
void DeleteStaticRtrNeighbor(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto oldStaticAddr = getStaticRtrAddr<family>(bus, params);
    if (oldStaticAddr.empty())
    {
        return;
    }

    ObjectLookupCache neighbors(bus, params, INTF_NEIGHBOR);
    auto neighbor =
        findStaticNeighbor<family>(bus, params, stdplus::fromStr<stdplus::In6Addr>(oldStaticAddr), neighbors);

    if (neighbor)
    {
        deleteObjectIfExists(bus, params.service, neighbor->path);
    }
}


/** @brief Deconfigures the IPv6 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The address index to operate on
 */
void deconfigureIfAddr6(sdbusplus::bus_t& bus, const ChannelParams& params,
                        uint8_t idx)
{
    auto ifaddr = getIfAddr<AF_INET6>(bus, params, idx, originsV6Static);
    if (ifaddr)
    {
        deleteObjectIfExists(bus, params.service, ifaddr->path);
    }
}

/** @brief Reconfigures the IPv6 address info configured for the interface
 *
 *  @param[in] bus     - The bus object used for lookups
 *  @param[in] params  - The parameters for the channel
 *  @param[in] idx     - The address index to operate on
 *  @param[in] address - The new address
 *  @param[in] prefix  - The new address prefix
 */
void reconfigureIfAddr6(sdbusplus::bus_t& bus, const ChannelParams& params,
                        uint8_t idx, stdplus::In6Addr address, uint8_t prefix)
{
    deconfigureIfAddr6(bus, params, idx);
    createIfAddr<AF_INET6>(bus, params, address, prefix, idx);
}

/** @brief Converts the AddressOrigin into an IPv6Source
 *
 *  @param[in] origin - The DBus Address Origin to convert
 *  @return The IPv6Source version of the origin
 */
IPv6Source originToSourceType(IP::AddressOrigin origin)
{
    switch (origin)
    {
        case IP::AddressOrigin::Static:
            return IPv6Source::Static;
        case IP::AddressOrigin::DHCP:
            return IPv6Source::DHCP;
        case IP::AddressOrigin::SLAAC:
            return IPv6Source::SLAAC;
        default:
        {
            auto originStr = sdbusplus::common::xyz::openbmc_project::network::
                convertForMessage(origin);
            log<level::ERR>(
                "Invalid IP::AddressOrigin conversion to IPv6Source",
                entry("ORIGIN=%s", originStr.c_str()));
            elog<InternalFailure>();
        }
    }
}

/** @brief Packs the IPMI message response with IPv6 address data
 *
 *  @param[out] ret     - The IPMI response payload to be packed
 *  @param[in]  channel - The channel id corresponding to an ethernet interface
 *  @param[in]  set     - The set selector for determining address index
 *  @param[in]  origins - Set of valid origins for address filtering
 */
void getLanIPv6Address(message::Payload& ret, uint8_t channel, uint8_t set,
                       const std::unordered_set<IP::AddressOrigin>& origins)
{
    auto source = IPv6Source::Static;
    bool enabled = false;
    stdplus::In6Addr addr{};
    uint8_t prefix{};
    auto status = IPv6AddressStatus::Disabled;

    auto ifaddr = channelCall<getIfAddr<AF_INET6>>(channel, set, origins);
    if (ifaddr)
    {
        source = originToSourceType(ifaddr->origin);
        enabled = (origins == originsV6Static);
        addr = ifaddr->address;
        prefix = ifaddr->prefix;
        status = IPv6AddressStatus::Active;
    }

    ret.pack(set);
    ret.pack(types::enum_cast<uint4_t>(source), uint3_t{}, enabled);
    ret.pack(stdplus::raw::asView<char>(addr));
    ret.pack(prefix);
    ret.pack(types::enum_cast<uint8_t>(status));
}

/** @brief Gets the vlan ID configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @return VLAN id or the standard 0 for no VLAN
 */
uint16_t getVLANProperty(sdbusplus::bus_t& bus, const ChannelParams& params)
{
    auto vlan = 0;
    // VLAN devices will always have a separate logical object
    if (params.ifPath == params.logicalPath)
    {
        return vlan;
    }
    try
    {
        vlan = std::get<uint32_t>(getDbusProperty(
            bus, params.service, params.logicalPath, INTF_VLAN, "Id"));
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("error in getVLANProperty", entry("name=%s", e.name()),
                        entry("what=%s", e.what()));
        elog<InternalFailure>();
     }

    if ((vlan & VLAN_VALUE_MASK) != vlan)
    {
        logWithChannel<level::ERR>(params, "networkd returned an invalid vlan",
                                   entry("VLAN=%" PRIu32, vlan));
        elog<InternalFailure>();
    }
    return vlan;
}

/** @brief Gets the vlan Priority configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 */
uint16_t getVLANPriority(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    auto vlan = 0;
    if (params.ifPath == params.logicalPath)
    {
        return vlan;
    }
    try
    {
        vlan = std::get<uint32_t>(getDbusProperty(
            bus, params.service, params.logicalPath, INTF_VLAN, "Priority"));
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("error in getVLANPriority", entry("name=%s", e.name()),
                        entry("what=%s", e.what()));
        elog<InternalFailure>();
    }
     return vlan;
}

/** @brief Sets the vlan Priority configured on the interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] vlan_priority - The priority for VLAN
 *  @return 1 if VLAN available else 0
 */
uint16_t setVLANPriority(sdbusplus::bus::bus& bus, const ChannelParams& params, uint32_t vlan_priority)
{
    // VLAN devices will always have a separate logical object
    if (params.ifPath == params.logicalPath)
    {
        return 0;
    }

    try
    {
        setDbusProperty(bus, params.service, params.logicalPath, INTF_VLAN,
                        "Priority", vlan_priority);
    }
     catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("error in setVLANPriority", entry("name=%s", e.name()),
                        entry("what=%s", e.what()));
        elog<InternalFailure>();
     }
     return 1;
}

/** @brief Creates a new VLAN on the specified interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] vlan   - The id of the new vlan
 */
void createVLAN(sdbusplus::bus::bus& bus, ChannelParams& params, uint16_t vlan)
{
    auto vlanid = getVLANProperty(bus, params);
    if (vlanid == vlan)
    {
        return;
    }
    try
    {
        auto req = bus.new_method_call(params.service.c_str(), std::string(PATH_ROOT).c_str(),
                                       INTF_VLAN_CREATE, "VLAN");
        req.append(params.ifname, static_cast<uint32_t>(vlan));
        bus.call_noreply(req);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("error in createVLAN", entry("name=%s", e.name()),
                        entry("what=%s", e.what()));
        elog<InternalFailure>();
    }
}

/** @brief Creates a new VLAN on the specified interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 */
int getVLANNum([[maybe_unused]]sdbusplus::bus::bus& bus, ChannelParams& params) {
    return params.numIntfVlan;
}

/** @brief delete a VLAN on the specified interface
 *
 *  @param[in] bus    - The bus object used for lookups
 *  @param[in] params - The parameters for the channel
 *  @param[in] vlan   - The new vlan id to use
 */
void deleteVLAN(sdbusplus::bus::bus& bus, ChannelParams& params, uint16_t vlan)
{
    auto logicalPath = params.ifPath + "_" + std::to_string(vlan);
    try {
        deleteObjectIfExists(bus, params.service, logicalPath);
    } catch (const std::exception &e) {
        logWithChannel<level::ERR>(params, "Invalid vlanID", entry("VLAN=%", vlan));
    }
}

template<int family>
void enableIPAddressing(sdbusplus::bus::bus& bus, ChannelParams& params, bool enabled) {
    in_addr ip;
    if (enabled && family == AF_INET) {
        setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, AddrFamily<family>::propertyIPEnabled, enabled);
    } // if
    else if (!enabled && family == AF_INET) {
        memset(&ip, 0, sizeof(in_addr));
        setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, AddrFamily<family>::propertyIPEnabled, enabled);
    } // else if
    else if (enabled && family == AF_INET6) {
        setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, AddrFamily<family>::propertyIPEnabled, enabled);
    } // else if
    else if (!enabled && family == AF_INET6) {
        setDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, AddrFamily<family>::propertyIPEnabled, enabled);
    }
}

template<int family>
bool getIPAddressingState(sdbusplus::bus::bus& bus, ChannelParams& params) {
    return std::get<bool>(getDbusProperty(bus, params.service, params.logicalPath, INTF_ETHERNET, AddrFamily<family>::propertyIPEnabled));
}

// We need to store this value so it can be returned to the client
// It is volatile so safe to store in daemon memory.
static std::unordered_map<uint8_t, SetStatus> setStatus;

// Until we have good support for fixed versions of IPMI tool
// we need to return the VLAN id for disabled VLANs. The value is only
// used for verification that a disable operation succeeded and will only
// be sent if our system indicates that vlans are disabled.
static std::unordered_map<uint8_t, uint16_t> lastDisabledVlan;

/** @brief Gets the set status for the channel if it exists
 *         Otherise populates and returns the default value.
 *
 *  @param[in] channel - The channel id corresponding to an ethernet interface
 *  @return A reference to the SetStatus for the channel
 */
SetStatus& getSetStatus(uint8_t channel)
{
    auto it = setStatus.find(channel);
    if (it != setStatus.end())
    {
        return it->second;
    }
    return setStatus[channel] = SetStatus::Complete;
}

/** @brief Unpacks the trivially copyable type from the message */
template <typename T>
static T unpackT(message::Payload& req)
{
    std::array<uint8_t, sizeof(T)> bytes;
    if (req.unpack(bytes) != 0)
    {
        throw ccReqDataLenInvalid;
    }
    return stdplus::raw::copyFrom<T>(bytes);
}

/** @brief Ensure the message is fully unpacked */
static void unpackFinal(message::Payload& req)
{
    if (!req.fullyUnpacked())
    {
        throw ccReqDataTruncated;
    }
}

/**
 * Define placeholder command handlers for the OEM Extension bytes for the Set
 * LAN Configuration Parameters and Get LAN Configuration Parameters
 * commands. Using "weak" linking allows the placeholder setLanOem/getLanOem
 * functions below to be overridden.
 * To create handlers for your own proprietary command set:
 *   Create/modify a phosphor-ipmi-host Bitbake append file within your Yocto
 *   recipe
 *   Create C++ file(s) that define IPMI handler functions matching the
 *     function names below (i.e. setLanOem). The default name for the
 *     transport IPMI commands is transporthandler_oem.cpp.
 *   Add:
 *      EXTRA_OEMESON:append = "-Dtransport-oem=enabled"
 *   Create a do_configure:prepend()/do_install:append() method in your
 *   bbappend file to copy the file to the build directory.
 *   Add:
 *   PROJECT_SRC_DIR := "${THISDIR}/${PN}"
 *   # Copy the "strong" functions into the working directory, overriding the
 *   # placeholder functions.
 *   do_configure:prepend(){
 *      cp -f ${PROJECT_SRC_DIR}/transporthandler_oem.cpp ${S}
 *   }
 *
 *   # Clean up after complilation has completed
 *   do_install:append(){
 *      rm -f ${S}/transporthandler_oem.cpp
 *   }
 *
 */

/**
 * Define the placeholder OEM commands as having weak linkage. Create
 * setLanOem, and getLanOem functions in the transporthandler_oem.cpp
 * file. The functions defined there must not have the "weak" attribute
 * applied to them.
 */
RspType<> setLanOem(uint8_t channel, uint8_t parameter, message::Payload& req)
    __attribute__((weak));
RspType<message::Payload> getLanOem(uint8_t channel, uint8_t parameter,
                                    uint8_t set, uint8_t block)
    __attribute__((weak));

RspType<> setLanOem(uint8_t, uint8_t, message::Payload& req)
{
    req.trailingOk = true;
    return response(ccParamNotSupported);
}

RspType<message::Payload> getLanOem(uint8_t, uint8_t, uint8_t, uint8_t)
{
    return response(ccParamNotSupported);
}

/**
 * @brief is a valid LAN channel.
 *
 * This function checks whether the input channel is a valid LAN channel or not.
 *
 * @param[in] channel: the channel number.
 * @return nullopt if the channel is invalid, false if the channel is not a LAN
 * channel, true if the channel is a LAN channel.
 **/
std::optional<bool> isLanChannel(uint8_t channel)
{
    ChannelInfo chInfo;
    auto cc = getChannelInfo(channel, chInfo);
    if (cc != ccSuccess)
    {
        return std::nullopt;
    }

    return chInfo.mediumType ==
           static_cast<uint8_t>(EChannelMediumType::lan8032);
}

/** @brief Sets the BMC  Generated ARP Response state on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] ARPResponse  - True: Enable BMC Generated ARP Response
 *                             False: Disable BMC Generated ARP Response
 */
void setARPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                       bool ARPResponse)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ARPCONTROL,
                    "ARPResponse", ARPResponse);
}

/** @brief Sets the BMC Generated GratuitousARP state on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] ARPResponse  - True: Enable BMC Generated GARP Response
 *                             False: Disable BMC Generated GARP Response
 */
void setGARPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                       bool GARPResponse)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ARPCONTROL,
                    "GratuitousARP", GARPResponse);
}

/** @brief Sets the GratuitousARP Interval on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @param[in] GARPInterval  - GratuitousARPInterval
 */
void setGARPIntervalProperty(sdbusplus::bus::bus& bus, const ChannelParams& params,
                      uint64_t GARPInterval)
{
    setDbusProperty(bus, params.service, params.logicalPath, INTF_ARPCONTROL,
                    "GratuitousARPInterval", GARPInterval);
}

/** @brief Gets the BMC  Generated ARP Response state on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @return status of ARP Response
 */
uint8_t getARPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    bool arpstatus = std::get<bool>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_ARPCONTROL, "ARPResponse"));

    return ((arpstatus)?2:0);
}

/** @brief Gets the BMC Generated GratuitousARP state on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @return status of GratuitousARP
 */
uint8_t getGARPProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    bool garpstatus = std::get<bool>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_ARPCONTROL, "GratuitousARP"));

    return ((garpstatus)?1:0);
}

/** @brief Gets the GratuitousARP Interval on the given interface
 *
 *  @param[in] bus           - The bus object used for lookups
 *  @param[in] params        - The parameters for the channel
 *  @return GARP Interval
 */
uint8_t getGARPIntervalProperty(sdbusplus::bus::bus& bus, const ChannelParams& params)
{
    uint64_t garpInterval = std::get<uint64_t>(getDbusProperty(
        bus, params.service, params.logicalPath, INTF_ARPCONTROL, "GratuitousARPInterval"));

    return (garpInterval/500);
}

RspType<> setLanInt(Context::ptr ctx, uint4_t channelBits, uint4_t reserved1,
                    uint8_t parameter, message::Payload& req)
{
    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);
    if (reserved1 || !isValidChannel(channel))
    {
        log<level::ERR>("Set Lan - Invalid field in request");
        req.trailingOk = true;
        return responseInvalidFieldRequest();
    }

    if (!isLanChannel(channel).value_or(false))
    {
        log<level::ERR>("Set Lan - Not a LAN channel");
        return responseInvalidFieldRequest();
    }

    if (!channelCall<getIPAddressingState<AF_INET>>(channel)) {
        if ( ( static_cast<LanParam>(parameter) >= LanParam::IP && static_cast<LanParam>(parameter) <= LanParam::SubnetMask )
            || ( static_cast<LanParam>(parameter) == LanParam::Gateway1 )
            || ( static_cast<LanParam>(parameter) == LanParam::Gateway1MAC )) {
            req.trailingOk = true;
            return responseCommandNotAvailable();
        }
    }

    if (!channelCall<getIPAddressingState<AF_INET6>>(channel)) {
        if ( static_cast<LanParam>(parameter) >= LanParam::IPv6Status && static_cast<LanParam>(parameter) <= LanParam::IPv6StaticRouter1PrefixValue ) {
            req.trailingOk = true;
            return responseCommandNotAvailable();
        }
    }

    switch (static_cast<LanParam>(parameter))
    {
        case LanParam::SetStatus:
        {
            uint2_t flag;
            uint6_t rsvd;
            if (req.unpack(flag, rsvd) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);
            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }
            auto status = static_cast<SetStatus>(static_cast<uint8_t>(flag));
            switch (status)
            {
                case SetStatus::Complete:
                {
                    getSetStatus(channel) = status;
                    return responseSuccess();
                }
                case SetStatus::InProgress:
                {
                    auto& storedStatus = getSetStatus(channel);
                    if (storedStatus == SetStatus::InProgress)
                    {
                        return response(ccParamSetLocked);
                    }
                    storedStatus = status;
                    return responseSuccess();
                }
                case SetStatus::Commit:
                   return response(ccParamNotSupported);
            }
            return response(ccParamNotSupported);
        }
        case LanParam::AuthSupport:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::AuthEnables:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IP:
        {
            if (channelCall<getEthProp<bool>>(channel, "DHCP4"))
            {
                return responseCommandNotAvailable();
            }
            auto ip = unpackT<stdplus::In4Addr>(req);
            unpackFinal(req);
            if (!ipmi::utility::ip_address::isValidIPv4Addr((in_addr*)(&ip.a), ipmi::utility::ip_address::Type::IP4_ADDRESS)) {
                return responseInvalidFieldRequest();
            }
            channelCall<reconfigureIfAddr4>(channel, ip, std::nullopt);
            return responseSuccess();
        }
        case LanParam::IPSrc:
        {
            uint4_t flag;
            uint4_t rsvd;
            if (req.unpack(flag, rsvd) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);
            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }
            switch (static_cast<IPSrc>(static_cast<uint8_t>(flag)))
            {
                case IPSrc::DHCP:
                    // The IPSrc IPMI command is only for IPv4
                    // management. Modifying IPv6 state is done using
                    // a completely different Set LAN Configuration
                    // subcommand.
                    channelCall<setEthProp<bool>>(channel, "DHCP4", true);
                    return responseSuccess();
                case IPSrc::Unspecified:
                    return responseInvalidFieldRequest();
                case IPSrc::Static:
                    channelCall<reconfigureIfAddr4>(channel, std::nullopt, std::nullopt);
                    channelCall<setEthProp<bool>>(channel, "DHCP4", false);
                    return responseSuccess();
                case IPSrc::BIOS:
                case IPSrc::BMC:
                    return responseInvalidFieldRequest();
            }
            return response(ccParamNotSupported);
        }
        case LanParam::MAC:
        {
            auto mac = unpackT<stdplus::EtherAddr>(req);
            unpackFinal(req);
            channelCall<setMACProperty>(channel, mac);
            return responseSuccess();
        }
        case LanParam::SubnetMask:
        {
            if (channelCall<getEthProp<bool>>(channel, "DHCP4"))
            {
                return responseCommandNotAvailable();
            }
            auto pfx = stdplus::maskToPfx(unpackT<stdplus::In4Addr>(req));
            unpackFinal(req);
            channelCall<reconfigureIfAddr4>(channel, std::nullopt, pfx);
            return responseSuccess();
        }
        case LanParam::BMCARPControl:
        {
            uint8_t enables;
            if (req.unpack(enables) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            switch (static_cast<ARPControlEnables>(enables))
            {
                case ARPControlEnables::BMCARPControlDisable:
                {
                    channelCall<setARPProperty>(channel, false);
                    channelCall<setGARPProperty>(channel, false);
                    return responseSuccess();
                }
                case ARPControlEnables::BMCGARPOnly:
                {
                    channelCall<setARPProperty>(channel, false);
                    channelCall<setGARPProperty>(channel, true);
                    return responseSuccess();
                }
                case ARPControlEnables::BMCARPOnly:
                {
                    channelCall<setARPProperty>(channel, true);
                    channelCall<setGARPProperty>(channel, false);
                    return responseSuccess();
                }
                case ARPControlEnables::BMCARPControlBoth:
                {
                    channelCall<setARPProperty>(channel, true);
                    channelCall<setGARPProperty>(channel, true);
                    return responseSuccess();
                }
            }
            return response(ccParamNotSupported);
        }
        case LanParam::GARPInterval:
        {
            uint8_t interval;
            if (req.unpack(interval) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            uint64_t garpInterval = interval * 500;
            channelCall<setGARPIntervalProperty>(channel, garpInterval);
            return responseSuccess();
        }
        case LanParam::Gateway1:
        {
            if (channelCall<getEthProp<bool>>(channel, "DHCP4"))
            {
                return responseCommandNotAvailable();
            }
            auto gateway = unpackT<stdplus::In4Addr>(req);
            unpackFinal(req);
            auto ifaddr = channelCall<getIfAddr4>(channel);
            if (ifaddr)
            {
                auto addr = ifaddr->address;
                auto netmask = stdplus::pfxToMask<stdplus::In4Addr>(ifaddr->prefix);
                if ((addr.a.s_addr & netmask.a.s_addr) != (gateway.a.s_addr & netmask.a.s_addr)) {
                    return responseInvalidFieldRequest();
                }
            }
            channelCall<setGatewayProperty<AF_INET>>(channel, gateway);
            return responseSuccess();
        }
        case LanParam::Gateway1MAC:
        {
            log<level::ERR>("Set Lan - Not allow to set gateway MAC Address");
            return response(ipmiCCWriteReadParameter);
        }
        case LanParam::VLANId:
        {
            uint12_t vlanData;
            uint3_t rsvd;
            bool vlanEnable;

            if (req.unpack(vlanData, rsvd, vlanEnable) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);

            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }

            uint16_t vlan = static_cast<uint16_t>(vlanData);

            if (!vlanEnable)
            {
                lastDisabledVlan[channel] = vlan;
                channelCall<deleteVLAN>(channel, vlan);
                return responseSuccess();
            }
            else if (vlan == 0 || vlan == VLAN_VALUE_MASK)
            {
                return responseInvalidFieldRequest();
            }
            if ( channelCall<getVLANNum>(channel) >= VLAN_MAX_NUM ) {
                log<level::ERR>("The number of VLAN interface of this parent interface is out of range, so skip this command...\n");
                return responseCommandNotAvailable();
            }
            else
                channelCall<createVLAN>(channel, vlan);
           return responseSuccess();
        }
        case LanParam::VLANPriority:
        {
            uint5_t reserved = 0;
            uint3_t vlanPriority = 0;
            if (req.unpack(vlanPriority) || req.unpack(reserved) ||
                (!req.fullyUnpacked()))
            {
                return responseReqDataLenInvalid();
            }

            if (((uint32_t)vlanPriority) > maxPriority)
            {
                return responseInvalidFieldRequest();
            }
            if (reserved)
            {
                return responseInvalidFieldRequest();
            }

            if (channelCall<setVLANPriority>(channel, (uint32_t)vlanPriority) ==
                0)
            {
                return responseCommandNotAvailable();
            }
            return responseSuccess();
        }
        case LanParam::CiphersuiteSupport:
        case LanParam::CiphersuiteEntries:
        case LanParam::IPFamilySupport:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IPFamilyEnables:
        {
            uint8_t enables;
            if (req.unpack(enables) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);
            switch (static_cast<IPFamilyEnables>(enables))
            {
                case IPFamilyEnables::DualStack:
                    channelCall<enableIPAddressing<AF_INET>>(channel, true);
                    channelCall<enableIPAddressing<AF_INET6>>(channel, true);
                    return responseSuccess();
                case IPFamilyEnables::IPv4Only:
                    channelCall<enableIPAddressing<AF_INET>>(channel, true);
                    channelCall<enableIPAddressing<AF_INET6>>(channel, false);
                    return responseSuccess();
                case IPFamilyEnables::IPv6Only:
                    channelCall<enableIPAddressing<AF_INET>>(channel, false);
                    channelCall<enableIPAddressing<AF_INET6>>(channel, true);
                    return responseSuccess();
            }
            return response(ccParamNotSupported);
        }
        case LanParam::IPv6Status:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IPv6StaticAddresses:
        {
            uint8_t set;
            uint7_t rsvd;
            bool enabled;
            uint8_t prefix;
            uint8_t status;
            if (req.unpack(set, rsvd, enabled) != 0)
            {
                return responseReqDataLenInvalid();
            }
            auto ip = unpackT<stdplus::In6Addr>(req);
            if (req.unpack(prefix, status) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);
            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }
            if (set >= MAX_IPV6_STATIC_ADDRESSES)
            {
                return responseParmOutOfRange();
            }

            if (enabled)
            {
                if (!ipmi::utility::ip_address::isValidIPv6Addr((in6_addr*)(&ip.__in6_u), ipmi::utility::ip_address::Type::IP6_ADDRESS)) {
                    return responseInvalidFieldRequest();
                }
                if (prefix < MIN_IPV6_PREFIX_LENGTH ||
                    prefix > MAX_IPV6_PREFIX_LENGTH)
                {
                    return responseParmOutOfRange();
                }
                if (channelCall<getEthProp<bool>>(channel, "DHCP6")) {
                    channelCall<setEthProp<bool>>(channel, "DHCP6", false);
                }
                channelCall<reconfigureIfAddr6>(channel, set, ip, prefix);
            }
            else
            {
                channelCall<deconfigureIfAddr6>(channel, set);
                auto nums = channelCall<getIfAddrNum<AF_INET6>>(channel, originsV6Static);
                if (nums == 0) {
                    channelCall<setEthProp<bool>>(channel, "DHCP6", true);

                    //We disable IPv6 Router Address Configuration static control field as only applicable when IPv6 is static
                    IPv6RouterControlFlag::StaticControl=0;
                    channelCall<setIPv6StaticRtr>(channel, IPv6RouterControlFlag::StaticControl);
                } // if
            }
            return responseSuccess();
        }
        case LanParam::IPv6DynamicAddresses:
        {
            req.trailingOk = true;
            return response(ccParamReadOnly);
        }
        case LanParam::IPv6RouterControl:
        {
            std::bitset<8> control;
            constexpr uint8_t reservedRACCBits = 0xfc;
            if (req.unpack(control) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);
            if (std::bitset<8> expected(control &
                                        std::bitset<8>(reservedRACCBits));
                expected.any())
            {
                return responseInvalidFieldRequest();
            }

            if (channelCall<getEthProp<bool>>(channel, "DHCP6"))
            {
                return responseCommandNotAvailable();
            }

            IPv6RouterControlFlag::StaticControl = control[IPv6RouterControlFlag::Static];

            bool enableRA = control[IPv6RouterControlFlag::Dynamic];
            channelCall<setEthProp<bool>>(channel, "IPv6AcceptRA", enableRA);
            
            bool staticRtr = channelCall<getEthProp<bool>>(channel, "IPv6EnableStaticRtr");
            if(staticRtr && control[IPv6RouterControlFlag::Dynamic]){
                channelCall<DeleteStaticRtrNeighbor<AF_INET6>>(channel);
            }

            bool enableStaticRtr = IPv6RouterControlFlag::StaticControl;
            channelCall<setIPv6StaticRtr>(channel, enableStaticRtr);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1IP:
        {
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            in6_addr routeAddr = unpackT<stdplus::In6Addr>(req);
            unpackFinal(req);
            if(!IPv6RouterControlFlag::StaticControl)
            {
                return responseCommandNotAvailable();
            }

            channelCall<setStaticRtrAddr>(channel, routeAddr);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1MAC:
        {
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            auto mac = unpackT<stdplus::EtherAddr>(req);
            unpackFinal(req);
            if(!IPv6RouterControlFlag::StaticControl)
            {
                return responseCommandNotAvailable();
            }
            
            channelCall<reconfigureGatewayMAC<AF_INET6>>(channel, mac);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1PrefixLength:
        {
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            uint8_t prefix;
            if (req.unpack(prefix) != 0)
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);
            if(!IPv6RouterControlFlag::StaticControl)
            {
                return responseCommandNotAvailable();
            }
            if (prefix > MAX_IPV6_PREFIX_LENGTH)
            {
                return responseInvalidFieldRequest();
            }
            channelCall<reconfigureGatewayPrefixLength<AF_INET6>>(channel, prefix);
            return responseSuccess();
        }
        case LanParam::IPv6StaticRouter1PrefixValue:
        {
            // Accept only null prefix value since currently not in use
            in6_addr ip = unpackT<stdplus::In6Addr>(req);
            unpackFinal(req);
            if(!IPv6RouterControlFlag::StaticControl)
            {
                return responseCommandNotAvailable();
            }

            if(IN6_IS_ADDR_UNSPECIFIED(&ip))
            {
                return responseSuccess();
            }
            else
            {
                return responseInvalidFieldRequest();
            }
        }
        case LanParam::cipherSuitePrivilegeLevels:
        {
            uint8_t rsvd;
            std::array<uint4_t, ipmi::maxCSRecords> cipherSuitePrivs;

            if (req.unpack(rsvd, cipherSuitePrivs))
            {
                return responseReqDataLenInvalid();
            }
            unpackFinal(req);

            if (rsvd)
            {
                return responseInvalidFieldRequest();
            }

            uint8_t resp = getCipherConfigObject(csPrivFileName,
                                                 csPrivDefaultFileName)
                               .setCSPrivilegeLevels(channel, cipherSuitePrivs);
            if (!resp)
            {
                return responseSuccess();
            }
            else
            {
                req.trailingOk = true;
                return response(resp);
            }
        }
    }

    if (parameter >= oemCmdStart)
    {
        return setLanOem(channel, parameter, req);
    }

    req.trailingOk = true;
    return response(ccParamNotSupported);
}

RspType<> setLan(Context::ptr ctx, uint4_t channelBits, uint4_t reserved1,
                 uint8_t parameter, message::Payload& req)
{
    try
    {
        return setLanInt(ctx, channelBits, reserved1, parameter, req);
    }
    catch (ipmi::Cc cc)
    {
        return response(cc);
    }
    catch (const sdbusplus::exception_t& e)
    {
        if (std::string_view{InvalidArgument::errName} == e.name())
        {
            return responseInvalidFieldRequest();
        }
        throw;
    }
}

RspType<message::Payload> getLan(Context::ptr ctx, uint4_t channelBits,
                                 uint3_t reserved, bool revOnly,
                                 uint8_t parameter, uint8_t set, uint8_t block)
{
    message::Payload ret;
    constexpr uint8_t current_revision = 0x11;
    ret.pack(current_revision);
    log<level::ERR>("Get Lan - Invalid field in request");

    if (revOnly)
    {
        return responseSuccess(std::move(ret));
    }

    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);
    if (reserved || !isValidChannel(channel))
    {
        log<level::ERR>("Get Lan - Invalid field in request");
        return responseInvalidFieldRequest();
    }

    if (!isLanChannel(channel).value_or(false))
    {
        log<level::ERR>("Set Lan - Not a LAN channel");
        return responseInvalidFieldRequest();
    }

    static std::vector<uint8_t> cipherList;
    static bool listInit = false;
    if (!listInit)
    {
        try
        {
            cipherList = cipher::getCipherList();
            listInit = true;
        }
        catch (const std::exception& e)
        {}
    }

    switch (static_cast<LanParam>(parameter))
    {
        case LanParam::SetStatus:
        {
            SetStatus status;
            try
            {
                status = setStatus.at(channel);
            }
            catch (const std::out_of_range&)
            {
                status = SetStatus::Complete;
            }
            ret.pack(types::enum_cast<uint2_t>(status), uint6_t{});
            return responseSuccess(std::move(ret));
        }
        case LanParam::AuthSupport:
        {
            std::bitset<6> support;
            ret.pack(support, uint2_t{});
            return responseSuccess(std::move(ret));
        }
        case LanParam::AuthEnables:
        {
            std::bitset<6> enables;
            ret.pack(enables, uint2_t{}); // Callback
            ret.pack(enables, uint2_t{}); // User
            ret.pack(enables, uint2_t{}); // Operator
            ret.pack(enables, uint2_t{}); // Admin
            ret.pack(enables, uint2_t{}); // OEM
            return responseSuccess(std::move(ret));
        }
        case LanParam::IP:
        {
            auto ifaddr = channelCall<getIfAddr4>(channel);
            stdplus::In4Addr addr{};
            if (ifaddr)
            {
                addr = ifaddr->address;
            }
            ret.pack(stdplus::raw::asView<char>(addr));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPSrc:
        {
            auto src = channelCall<getEthProp<bool>>(channel, "DHCP4")
                           ? IPSrc::DHCP
                           : IPSrc::Static;
            ret.pack(types::enum_cast<uint4_t>(src), uint4_t{});
            return responseSuccess(std::move(ret));
        }
        case LanParam::MAC:
        {
            auto mac = channelCall<getMACProperty>(channel);
            ret.pack(stdplus::raw::asView<char>(mac));
            return responseSuccess(std::move(ret));
        }
        case LanParam::SubnetMask:
        {
            auto ifaddr = channelCall<getIfAddr4>(channel);
            uint8_t prefix = AddrFamily<AF_INET>::defaultPrefix;
            if (ifaddr)
            {
                prefix = ifaddr->prefix;
            }
            auto netmask = stdplus::pfxToMask<stdplus::In4Addr>(prefix);
            ret.pack(stdplus::raw::asView<char>(netmask));
            return responseSuccess(std::move(ret));
        }
        case LanParam::BMCARPControl:
        {
            uint8_t arp = channelCall<getARPProperty>(channel);
            uint8_t garp = channelCall<getGARPProperty>(channel);
            arp = (arp|garp);
            ret.pack(stdplus::raw::asView<char>(arp));
            return responseSuccess(std::move(ret));
        }
        case LanParam::GARPInterval:
        {
            uint8_t interval = channelCall<getGARPIntervalProperty>(channel);
            ret.pack(stdplus::raw::asView<char>(interval));
            return responseSuccess(std::move(ret));
        }
        case LanParam::Gateway1:
        {
            auto gateway = channelCall<getGatewayProperty<AF_INET>>(channel);
            ret.pack(stdplus::raw::asView<char>(
                gateway.value_or(stdplus::In4Addr{})));
            return responseSuccess(std::move(ret));
        }
        case LanParam::Gateway1MAC:
        {
            stdplus::EtherAddr mac{};
            auto neighbor = channelCall<getGatewayNeighbor<AF_INET>>(channel);
            if (neighbor)
            {
                mac = neighbor->mac;
            }
            ret.pack(stdplus::raw::asView<char>(mac));
            return responseSuccess(std::move(ret));
        }
        case LanParam::VLANId:
        {
            uint16_t vlan = channelCall<getVLANProperty>(channel);
            if (vlan != 0)
            {
                vlan |= VLAN_ENABLE_FLAG;
            }
            else
            {
                vlan = lastDisabledVlan[channel];
            }
            ret.pack(static_cast<uint8_t>(vlan & 0x00FF));
            ret.pack(static_cast<uint8_t>((vlan & 0xFF00) >> 8));
            return responseSuccess(std::move(ret));
        }
        case LanParam::CiphersuiteSupport:
        {
            if (getChannelSessionSupport(channel) ==
                EChannelSessSupported::none)
            {
                return responseInvalidFieldRequest();
            }
            if (!listInit)
            {
                return responseUnspecifiedError();
            }
            ret.pack(static_cast<uint8_t>(cipherList.size() - 1));
            return responseSuccess(std::move(ret));
        }
        case LanParam::CiphersuiteEntries:
        {
            if (getChannelSessionSupport(channel) ==
                EChannelSessSupported::none)
            {
                return responseInvalidFieldRequest();
            }
            if (!listInit)
            {
                return responseUnspecifiedError();
            }
            ret.pack(cipherList);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPFamilySupport:
        {
            std::bitset<8> support;
            support[IPFamilySupportFlag::IPv6Only] = 1;
            support[IPFamilySupportFlag::DualStack] = 1;
            support[IPFamilySupportFlag::IPv6Alerts] = 1;
            ret.pack(support);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPFamilyEnables:
        {
            uint8_t enable = 0;
            auto ipv4 = channelCall<getIPAddressingState<AF_INET>>(channel);
            auto ipv6 = channelCall<getIPAddressingState<AF_INET6>>(channel);
            if (ipv4 && ipv6) {
                enable = 2;
            }
            else if (ipv4 && !ipv6) {
                enable = 0;
            }
            else if (!ipv4 && ipv6) {
                enable = 1;
            }

            ret.pack(enable);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6Status:
        {
            ret.pack(MAX_IPV6_STATIC_ADDRESSES);
            ret.pack(MAX_IPV6_DYNAMIC_ADDRESSES);
            std::bitset<8> support;
            support[IPv6StatusFlag::DHCP] = 1;
            support[IPv6StatusFlag::SLAAC] = 1;
            ret.pack(support);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticAddresses:
        {
            if (set >= MAX_IPV6_STATIC_ADDRESSES)
            {
                return responseParmOutOfRange();
            }
            getLanIPv6Address(ret, channel, set, originsV6Static);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6DynamicAddresses:
        {
            if (set >= MAX_IPV6_DYNAMIC_ADDRESSES)
            {
                return responseParmOutOfRange();
            }
            getLanIPv6Address(ret, channel, set, originsV6Dynamic);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6RouterControl:
        {
            std::bitset<8> control;
            control[IPv6RouterControlFlag::Dynamic] =
                channelCall<getEthProp<bool>>(channel, "IPv6AcceptRA");
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            control[IPv6RouterControlFlag::Static] = IPv6RouterControlFlag::StaticControl;
            ret.pack(control);
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1IP:
        {
            std::string routerAddr;
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            if (!channelCall<getEthProp<bool>>(channel, "IPv6AcceptRA"))
            {
                routerAddr = channelCall<getStaticRtrAddr<AF_INET6>>(channel);
            }

            if(!routerAddr.empty()){
                ret.pack(stdplus::raw::asView<char>(stdplus::fromStr<stdplus::In6Addr>(routerAddr)));
            }
            else{
                ret.pack(stdplus::raw::asView<char>(stdplus::In6Addr{}));
            }

            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1MAC:
        {
            stdplus::EtherAddr mac{};
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            auto neighbor = channelCall<getGatewayNeighbor<AF_INET6>>(channel);
            if(IPv6RouterControlFlag::StaticControl)
            {
                auto neighbor = channelCall<getStaticRtrNeighbor<AF_INET6>>(channel);
                if (neighbor)
                {
                    mac = neighbor->mac;
                }
            }
            ret.pack(stdplus::raw::asView<char>(mac));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1PrefixLength:
        {
            uint8_t prefixLength = 0;
            IPv6RouterControlFlag::StaticControl = channelCall<getIPv6StaticRtr>(channel);
            if(IPv6RouterControlFlag::StaticControl)
            {
                auto neighbor = channelCall<getStaticRtrNeighbor<AF_INET6>>(channel);
                if (neighbor)
                {
                    prefixLength = neighbor->prefixLength;
                }
            }
            ret.pack(UINT8_C(prefixLength));
            return responseSuccess(std::move(ret));
        }
        case LanParam::IPv6StaticRouter1PrefixValue:
        {
            ret.pack(stdplus::raw::asView<char>(stdplus::In6Addr{}));
            return responseSuccess(std::move(ret));
        }
        case LanParam::VLANPriority:
        {
            uint8_t vlanPriority = channelCall<getVLANPriority>(channel);
            ret.pack(vlanPriority);
            return responseSuccess(std::move(ret));
        }
        case LanParam::cipherSuitePrivilegeLevels:
        {
            std::array<uint4_t, ipmi::maxCSRecords> csPrivilegeLevels;

            uint8_t resp =
                getCipherConfigObject(csPrivFileName, csPrivDefaultFileName)
                    .getCSPrivilegeLevels(channel, csPrivilegeLevels);
            if (!resp)
            {
                constexpr uint8_t reserved1 = 0x00;
                ret.pack(reserved1, csPrivilegeLevels);
                return responseSuccess(std::move(ret));
            }
            else
            {
                return response(resp);
            }
        }
    }

    if (parameter >= oemCmdStart)
    {
        return getLanOem(channel, parameter, set, block);
    }

    return response(ccParamNotSupported);
}

constexpr const char* solInterface = "xyz.openbmc_project.Ipmi.SOL";
constexpr const char* solPath = "/xyz/openbmc_project/ipmi/sol/";
constexpr const uint16_t solDefaultPort = 623;

constexpr uint8_t progressMask = 0x03;
constexpr uint8_t retryMask = 0x07;


constexpr Cc ccSetInProgressActive = 0x81;

static inline auto responseParmNotSupported()
{
    return response(ipmiCCParamNotSupported);
}
static inline auto responseSetInProgressActive()
{
    return response(ccSetInProgressActive);
}

RspType<> setSolConfParams(Context::ptr ctx, uint4_t channelBits,
                           uint4_t /*reserved*/, uint8_t parameter,
                           message::Payload& req)
{
    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);

    if (!isValidChannel(channel))
    {
        log<level::ERR>("Set Sol Config - Invalid channel in request");
        return responseInvalidFieldRequest();
    }

    std::string solService{};
    std::string solPathWitheEthName = solPath + ipmi::getChannelName(channel);

    if (ipmi::getService(ctx, solInterface, solPathWitheEthName, solService))
    {
        log<level::ERR>("Set Sol Config - Invalid solInterface",
                        entry("SERVICE=%s", solService.c_str()),
                        entry("OBJPATH=%s", solPathWitheEthName.c_str()),
                        entry("INTERFACE=%s", solInterface));
        return responseInvalidFieldRequest();
    }

    switch (static_cast<SolConfParam>(parameter))
    {
        case SolConfParam::Progress:
        {
            uint8_t progress = 0;
	    uint8_t currentProgress = 0;
            if (req.unpack(progress) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

	    if ( !(progress < progressMask) )
	    {
                return responseInvalidFieldRequest();
	    }


	    if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName, solInterface, "Progress", currentProgress))
            {
                return responseUnspecifiedError();
            }

	    if ((currentProgress == 1) && (progress == 1))
            {
                return responseSetInProgressActive();
            }

	    if (progress == 2)
	    {
                return responseParmNotSupported();
	    }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName, solInterface, "Progress", progress))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Enable:
        {
            bool enable;
            uint7_t reserved2;

            if (req.unpack(enable, reserved2) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

	    if (reserved2 !=0)
	    {
		return responseInvalidFieldRequest();
	    }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Enable", enable))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Authentication:
        {
            uint4_t privilegeBits{};
            uint2_t reserved2{};
            bool forceAuth = false;
            bool forceEncrypt = false;

            if (req.unpack(privilegeBits, reserved2, forceAuth, forceEncrypt) !=
                    0 ||
                !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

	    if( reserved2 != 0)
	    {
		return responseInvalidFieldRequest();
	    }
            

            uint8_t privilege = static_cast<uint8_t>(privilegeBits);
            if (privilege < static_cast<uint8_t>(Privilege::User) ||
                privilege > static_cast<uint8_t>(Privilege::Oem))
            {
                return ipmi::responseInvalidFieldRequest();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Privilege", privilege))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceEncryption",
                                      forceEncrypt))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceAuthentication",
                                      forceAuth))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Accumulate:
        {
            uint8_t interval;
            uint8_t threshold;
            if (req.unpack(interval, threshold) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (threshold == 0 || interval == 0) 
            {
                return responseInvalidFieldRequest();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "AccumulateIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Threshold", threshold))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Retry:
        {
            uint3_t countBits;
            uint5_t reserved2;
            uint8_t interval;

            if (req.unpack(countBits, reserved2, interval) != 0 ||
                !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

	    if( reserved2 != 0 || (countBits > retryMask))
	    {
		return responseInvalidFieldRequest();
	    }



            uint8_t count = static_cast<uint8_t>(countBits);
            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryCount", count))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::setDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }
            break;
        }
        case SolConfParam::Port:
        {
            return response(ipmiCCWriteReadParameter);
        }
        case SolConfParam::NonVbitrate:
	{
	    uint8_t encodedBitRate = 0;
	    uint64_t baudRate = 0;
	    if (req.unpack(encodedBitRate) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
	    switch (encodedBitRate)
            {
                case 0x06:
                    baudRate = 9600;
                    break;
                case 0x07:
                    baudRate = 19200;
                    break;
                case 0x08:
                    baudRate = 38400;
                    break;
                case 0x09:
                    baudRate = 57600;
                    break;
                case 0x0a:
                    baudRate = 115200;
                    break;
                default:
		    return responseInvalidFieldRequest();
            }
	    if (ipmi::setDbusProperty(
                    ctx, "xyz.openbmc_project.Console.default",
                    "/xyz/openbmc_project/console/default",
                    "xyz.openbmc_project.Console.UART", "Baud", baudRate))
            {
                return ipmi::responseUnspecifiedError();
            }
	    break;

	}
        case SolConfParam::Vbitrate:
            return response(ipmiCCParamNotSupported);
        case SolConfParam::Channel:
            return response(ipmiCCWriteReadParameter);
        default:
            return response(ipmiCCParamNotSupported);
    }
    return responseSuccess();
}

RspType<message::Payload> getSolConfParams(Context::ptr ctx,
                                           uint4_t channelBits,
                                           uint3_t /*reserved*/, bool revOnly,
                                           uint8_t parameter, uint8_t /*set*/,
                                           uint8_t /*block*/)
{
    message::Payload ret;
    constexpr uint8_t current_revision = 0x11;
    ret.pack(current_revision);
    if (revOnly)
    {
        return responseSuccess(std::move(ret));
    }

    const uint8_t channel = convertCurrentChannelNum(
        static_cast<uint8_t>(channelBits), ctx->channel);

    if (!isValidChannel(channel))
    {
        log<level::ERR>("Get Sol Config - Invalid channel in request");
        return responseInvalidFieldRequest();
    }

    std::string solService{};
    std::string solPathWitheEthName = solPath + ipmi::getChannelName(channel);

    if (ipmi::getService(ctx, solInterface, solPathWitheEthName, solService))
    {
        log<level::ERR>("Set Sol Config - Invalid solInterface",
                        entry("SERVICE=%s", solService.c_str()),
                        entry("OBJPATH=%s", solPathWitheEthName.c_str()),
                        entry("INTERFACE=%s", solInterface));
        return responseInvalidFieldRequest();
    }

    switch (static_cast<SolConfParam>(parameter))
    {
        case SolConfParam::Progress:
        {
            uint8_t progress;
            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Progress", progress))
            {
                return responseUnspecifiedError();
            }
            ret.pack(progress);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Enable:
        {
            bool enable{};
            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Enable", enable))
            {
                return responseUnspecifiedError();
            }
            ret.pack(enable, uint7_t{});
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Authentication:
        {
            // 4bits, cast when pack
            uint8_t privilege;
            bool forceAuth = false;
            bool forceEncrypt = false;

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Privilege", privilege))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceAuthentication",
                                      forceAuth))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "ForceEncryption",
                                      forceEncrypt))
            {
                return responseUnspecifiedError();
            }
            ret.pack(uint4_t{privilege}, uint2_t{}, forceAuth, forceEncrypt);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Accumulate:
        {
            uint8_t interval{}, threshold{};

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "AccumulateIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "Threshold", threshold))
            {
                return responseUnspecifiedError();
            }
            ret.pack(interval, threshold);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Retry:
        {
            // 3bits, cast when cast
            uint8_t count{};
            uint8_t interval{};

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryCount", count))
            {
                return responseUnspecifiedError();
            }

            if (ipmi::getDbusProperty(ctx, solService, solPathWitheEthName,
                                      solInterface, "RetryIntervalMS",
                                      interval))
            {
                return responseUnspecifiedError();
            }
            ret.pack(uint3_t{count}, uint5_t{}, interval);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Port:
        {
            auto port = solDefaultPort;
            ret.pack(static_cast<uint16_t>(port));
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Channel:
        {
            ret.pack(channel);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::NonVbitrate:
        {
            uint64_t baudRate;
            uint8_t encodedBitRate = 0;
            if (ipmi::getDbusProperty(
                    ctx, "xyz.openbmc_project.Console.default",
                    "/xyz/openbmc_project/console/default",
                    "xyz.openbmc_project.Console.UART", "Baud", baudRate))
            {
                return ipmi::responseUnspecifiedError();
            }
            switch (baudRate)
            {
                case 9600:
                    encodedBitRate = 0x06;
                    break;
                case 19200:
                    encodedBitRate = 0x07;
                    break;
                case 38400:
                    encodedBitRate = 0x08;
                    break;
                case 57600:
                    encodedBitRate = 0x09;
                    break;
                case 115200:
                    encodedBitRate = 0x0a;
                    break;
                default:
                    break;
            }
            ret.pack(encodedBitRate);
            return responseSuccess(std::move(ret));
        }
        case SolConfParam::Vbitrate:
        default:
            return response(ipmiCCParamNotSupported);
    }

    return response(ccParamNotSupported);
}

} // namespace transport
} // namespace ipmi

void register_netfn_transport_functions() __attribute__((constructor));

void register_netfn_transport_functions()
{
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdSetLanConfigParameters,
                          ipmi::Privilege::Admin, ipmi::transport::setLan);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdGetLanConfigParameters,
                          ipmi::Privilege::Operator, ipmi::transport::getLan);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdSetSolConfigParameters,
                          ipmi::Privilege::Admin,
                          ipmi::transport::setSolConfParams);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnTransport,
                          ipmi::transport::cmdGetSolConfigParameters,
                          ipmi::Privilege::User,
                          ipmi::transport::getSolConfParams);
}
