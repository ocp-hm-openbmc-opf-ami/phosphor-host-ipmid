#pragma once

#include <ipmid/api-types.hpp>
#include <stdplus/zstring_view.hpp>

#include <cstdint>

namespace ipmi
{
namespace transport
{

using stdplus::operator""_zsv;
using namespace phosphor::logging;
// D-Bus Network Daemon definitions
constexpr auto PATH_ROOT = "/xyz/openbmc_project/network"_zsv;
constexpr auto INTF_ETHERNET = "xyz.openbmc_project.Network.EthernetInterface";
constexpr auto INTF_IP = "xyz.openbmc_project.Network.IP";
constexpr auto INTF_IP_CREATE = "xyz.openbmc_project.Network.IP.Create";
constexpr auto INTF_MAC = "xyz.openbmc_project.Network.MACAddress";
constexpr auto INTF_NEIGHBOR = "xyz.openbmc_project.Network.Neighbor";
constexpr auto INTF_NEIGHBOR_CREATE_STATIC =
    "xyz.openbmc_project.Network.Neighbor.CreateStatic";
constexpr auto INTF_VLAN = "xyz.openbmc_project.Network.VLAN";
constexpr auto INTF_VLAN_CREATE = "xyz.openbmc_project.Network.VLAN.Create";
constexpr auto INTF_ARPCONTROL = "xyz.openbmc_project.Network.ARPControl";
constexpr auto maxPriority = 7;
constexpr auto CHANNEL_INTF_SERVICE="xyz.openbmc_project.Ipmi.Channel";
constexpr auto SESSION_ROOT_PATH = "/xyz/openbmc_project/ipmi/session";
constexpr auto INTF_IPHEADER = "xyz.openbmc_project.Ipmi.IPHeader";

/** @brief IPMI LAN Parameters */
enum class LanParam : uint8_t
{
    SetStatus = 0,
    AuthSupport = 1,
    AuthEnables = 2,
    IP = 3,
    IPSrc = 4,
    MAC = 5,
    SubnetMask = 6,
    IPv4HeaderParam = 7,
    BMCARPControl = 10,
    GARPInterval = 11,
    Gateway1 = 12,
    Gateway1MAC = 13,
    BackupGateway=14,
    BackupGatewayMAC=15,
    VLANId = 20,
    VLANPriority = 21,
    CiphersuiteSupport = 22,
    CiphersuiteEntries = 23,
    cipherSuitePrivilegeLevels = 24,
    IPFamilySupport = 50,
    IPFamilyEnables = 51,
    IPv6HeaderStaticTrafficClass = 52,
    IPv6HeaderStaticHopLimit = 53,
    IPv6Status = 55,
    IPv6StaticAddresses = 56,
    IPv6DynamicAddresses = 59,
    IPv6DHCPv6DynamicDUIDStorageLength = 60,
    IPv6DHCPv6DynamicDUIDs = 61,
    IPv6DHCPv6TimingConfigurationSupport = 62,
    IPv6DHCPv6TimingConfiguration = 63,
    IPv6RouterControl = 64,
    IPv6StaticRouter1IP = 65,
    IPv6StaticRouter1MAC = 66,
    IPv6StaticRouter1PrefixLength = 67,
    IPv6StaticRouter1PrefixValue = 68,
    IPv6StaticRouter2IP = 69,
    IPv6StaticRouter2MAC = 70,
    IPv6StaticRouter2PrefixLength = 71,
    IPv6StaticRouter2PrefixValue = 72,
    IPv6DynamicRouterInfoSets=73,
    IPv6DynamicRouterInfoIPAddress=74,
    IPv6DynamicRouterInfoMACAddress=75,
    IPv6DynamicRouterInfoPrefixLength=76,
    IPv6DynamicRouterInfoPrefixValue=77,
    IPv6SLAACTimingConfigurationSupport=79,
    IPv6SLAACTimingConfiguration=80
};

/** @brief IPMI IP Origin Types */
enum class IPSrc : uint8_t
{
    Unspecified = 0,
    Static = 1,
    DHCP = 2,
    BIOS = 3,
    BMC = 4,
};

/** @brief IPMI ARP Control Enables Flag */
enum class ARPControlEnables : uint8_t
{
    BMCARPControlDisable = 0,
    BMCGARPOnly = 1,
    BMCARPOnly = 2,
    BMCARPControlBoth = 3,
};

/** @brief IPMI Set Status */
enum class SetStatus : uint8_t
{
    Complete = 0,
    InProgress = 1,
    Commit = 2,
    Reserved = 3,
};

/** @brief IPMI Family Suport Bits */
namespace IPFamilySupportFlag
{
constexpr uint8_t IPv6Only = 0;
constexpr uint8_t DualStack = 1;
constexpr uint8_t IPv6Alerts = 2;
} // namespace IPFamilySupportFlag

/** @brief IPMI IPFamily Enables Flag */
enum class IPFamilyEnables : uint8_t
{
    IPv4Only = 0,
    IPv6Only = 1,
    DualStack = 2,
};

/** @brief IPMI IPv6 Dyanmic Status Bits */
namespace IPv6StatusFlag
{
constexpr uint8_t DHCP = 0;
constexpr uint8_t SLAAC = 1;
}; // namespace IPv6StatusFlag

/** @brief IPMI IPv6 Source */
enum class IPv6Source : uint8_t
{
    Static = 0,
    SLAAC = 1,
    DHCP = 2,
};

/** @brief IPMI IPv6 Address Status */
enum class IPv6AddressStatus : uint8_t
{
    Active = 0,
    Disabled = 1,
};

namespace IPv6RouterControlFlag
{
constexpr uint8_t Static = 0;     //IPv6 Router Address Configuration Control Bits
constexpr uint8_t Dynamic = 1;   //IPv6 Router Address Configuration Control Bits
uint8_t StaticControl = 0;
constexpr uint8_t Gateway6Idx=0;
constexpr uint8_t PrefixIdx=1;
constexpr uint8_t PrefixLenIdx=2;
constexpr uint8_t Gateway6MACIdx=3;
constexpr uint8_t IPV6STRLEN = 16;
constexpr uint8_t MACSTRLEN = 6;
constexpr uint8_t MAX_IPV6_DYNAMIC_ROUTER_INFO_SETS = 4;
using RACFG_T = std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, uint8_t, std::vector<uint8_t>>;
}; // namespace IPv6RouterControlFlag

// LAN Handler specific response codes
constexpr Cc ccParamNotSupported = 0x80;
constexpr Cc ccParamSetLocked = 0x81;
constexpr Cc ccParamReadOnly = 0x82;

// VLANs are a 12-bit value
constexpr uint16_t VLAN_VALUE_MASK = 0x0fff;
constexpr uint16_t VLAN_ENABLE_FLAG = 0x8000;
constexpr uint8_t VLAN_MAX_NUM = 2;

// Arbitrary v6 Address Limits to prevent too much output in ipmitool
constexpr uint8_t MAX_IPV6_STATIC_ADDRESSES = 16;
constexpr uint8_t MAX_IPV6_DYNAMIC_ADDRESSES = 16;

// Prefix length limits of phosphor-networkd
constexpr uint8_t MIN_IPV4_PREFIX_LENGTH = 1;
constexpr uint8_t MAX_IPV4_PREFIX_LENGTH = 32;
constexpr uint8_t MIN_IPV6_PREFIX_LENGTH = 1;
constexpr uint8_t MAX_IPV6_PREFIX_LENGTH = 128;
constexpr char propertyLinkLocal[] = "LinkLocalAutoConf";

/** @enum SolConfParam
 *
 *  using for Set/Get SOL configuration parameters command.
 */
enum class SolConfParam : uint8_t
{
    Progress,       //!< Set In Progress.
    Enable,         //!< SOL Enable.
    Authentication, //!< SOL Authentication.
    Accumulate,     //!< Character Accumulate Interval & Send Threshold.
    Retry,          //!< SOL Retry.
    NonVbitrate,    //!< SOL non-volatile bit rate.
    Vbitrate,       //!< SOL volatile bit rate.
    Channel,        //!< SOL payload channel.
    Port,           //!< SOL payload port.
};

constexpr uint8_t ipmiCCParamNotSupported = 0x80;
constexpr uint8_t ipmiCCWriteReadParameter = 0x82;

/** @enum DHCPv6TimingParamIndex
 *
 */
enum class DHCPv6TimingParamIndex : uint8_t
{
    SOL_MAX_DELAY = 0,
    SOL_TIMEOUT = 1,
    SOL_MAX_RT = 2,
    REQ_TIMEOUT = 3,
    REQ_MAX_RT = 4,
    REQ_MAX_RC = 5,
    CNF_MAX_DELAY = 6,
    CNF_TIMEOUT = 7,
    CNF_MAX_RT = 8,
    CNF_MAX_RD = 9,
    REN_TIMEOUT = 10,
    REN_MAX_RT = 11,
    REB_TIMEOUT = 12,
    REB_MAX_RT = 13,
    INF_MAX_DELAY = 14,
    INF_TIMEOUT = 15,
    INF_MAX_RT = 16,
    REL_TIMEOUT = 17,
    REL_MAX_RC = 18,
    DEC_TIMEOUT = 19,
    DEC_MAX_RC = 20,
    HOP_COUNT_LIMIT = 21
};

namespace DHCPv6TimingParamMaxLimit
{
    constexpr uint8_t SOL_MAX_DELAY = 254;
    constexpr uint8_t SOL_TIMEOUT = 254;
    constexpr uint8_t REQ_TIMEOUT = 254;
    constexpr uint8_t REQ_MAX_RC = 101;
    constexpr uint8_t INF_TIMEOUT = 254;
}; // namespace DHCPv6TimingParamMaxLimit

namespace SLAACTimingParamIndex
{
    constexpr int MaxRtrSolicitationDelay = 0;
    constexpr int RtrSolicitationInterval = 1;
    constexpr int MaxRtrSolicitations = 2;
    constexpr int DupAddrDetectTransmits = 3;
    constexpr int MaxMulticastSolicit = 4;
    constexpr int MaxUnicastSolicit = 5;
    constexpr int MaxAnycastDelayTime = 6;
    constexpr int MaxNeighborAdvertisement = 7;
    constexpr int ReachableTime = 8;
    constexpr int RetransTimer = 9;
    constexpr int DelayFirstProbeTime = 10;
    constexpr int MaxRandomFactor = 11;
    constexpr int MinRandomFactor = 12;
};

namespace SLAACTimingParamMaxLimit
{
    constexpr uint8_t MaxRtrSolicitations = 100;
    constexpr uint8_t DupAddrDetectTransmits = 101;
    constexpr uint8_t MaxMulticastSolicit = 100;
    constexpr uint8_t MaxUnicastSolicit = 100;
}; // namespace DHCPv6TimingParamDefault

} // namespace transport
} // namespace ipmi
