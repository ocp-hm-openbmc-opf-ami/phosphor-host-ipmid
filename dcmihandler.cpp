#include "config.h"

#include "dcmihandler.hpp"

#include "user_channel/channel_layer.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>

#include <bitset>
#include <cmath>
#include <fstream>
#include <variant>

using namespace phosphor::logging;
using sdbusplus::server::xyz::openbmc_project::network::EthernetInterface;

using InternalFailure =
    sdbusplus::error::xyz::openbmc_project::common::InternalFailure;

void register_netfn_dcmi_functions() __attribute__((constructor));

constexpr auto pcapPath = "/xyz/openbmc_project/control/host0/power_cap";
constexpr auto pcapInterface = "xyz.openbmc_project.Control.Power.Cap";

constexpr auto powerCapProp = "PowerCap";
constexpr auto powerCapEnableProp = "PowerCapEnable";

using namespace phosphor::logging;

namespace dcmi
{
constexpr auto assetTagMaxOffset = 62;
constexpr auto assetTagMaxSize = 63;
constexpr auto maxBytes = 16;
constexpr size_t maxCtrlIdStrLen = 64;

constexpr uint8_t parameterRevision = 2;
constexpr uint8_t specMajorVersion = 1;
constexpr uint8_t specMinorVersion = 5;
constexpr auto sensorValueIntf = "xyz.openbmc_project.Sensor.Value";
constexpr auto sensorValueProp = "Value";
constexpr uint8_t configParameterRevision = 1;
constexpr auto option12Mask = 0x01;
constexpr auto option60Mask = 0x02;
constexpr auto option60And12Mask = 0x03;
constexpr uint8_t activateDhcpReply = 0x00;
constexpr uint8_t dhcpTiming1 = 0x04;  // 4 sec
constexpr uint16_t dhcpTiming2 = 0x78; // 120 sec
constexpr uint16_t dhcpTiming3 = 0x40; // 60 sec
// When DHCP Option 12 is enabled the string "SendHostName=true" will be
// added into n/w configuration file and the parameter
// SendHostNameEnabled will set to true.
constexpr auto dhcpOpt12Enabled = "SendHostNameEnabled";
constexpr auto dhcpOption60Enabled = "VendorClassIdentifier";
constexpr auto dhcpOption43Enabled = "SetVendorOption";
constexpr auto dhcpOption43Disabled = "DelVendorOption";

enum class DCMIConfigParameters : uint8_t
{
    ActivateDHCP = 1,
    DiscoveryConfig,
    DHCPTiming1,
    DHCPTiming2,
    DHCPTiming3,
};

// Refer Table 6-14, DCMI Entity ID Extension, DCMI v1.5 spec
static const std::map<uint8_t, std::string> entityIdToName{
    {0x40, "inlet"}, {0x37, "inlet"},     {0x41, "cpu"},
    {0x03, "cpu"},   {0x42, "baseboard"}, {0x07, "baseboard"}};

nlohmann::json parseJSONConfig(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        lg2::error("Temperature readings JSON file not found");
        elog<InternalFailure>();
    }

    auto data = nlohmann::json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        lg2::error("Temperature readings JSON parser failure");
        elog<InternalFailure>();
    }

    return data;
}

void restartSystemdUnit(const std::string& unit)
 {
     sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
 
     try
     {
         auto method = bus.new_method_call(systemBusName, systemPath,
                                           systemIntf, "RestartUnit");
         method.append(unit.c_str(), "replace");
         bus.call_noreply(method);
     }
     catch (const sdbusplus::exception::SdBusError& ex)
     {
         log<level::ERR>("Failed to restart nslcd service",
                         entry("ERR=%s", ex.what()));
         elog<InternalFailure>();
     }
 }

bool isDCMIPowerMgmtSupported()
{
    static bool parsed = false;
    static bool supported = false;
    if (!parsed)
    {
        auto data = parseJSONConfig(gDCMICapabilitiesConfig);

        supported = (gDCMIPowerMgmtSupported ==
                     data.value(gDCMIPowerMgmtCapability, 0));
    }
    return supported;
}

std::optional<uint32_t> getPcap(ipmi::Context::ptr& ctx)
{
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, pcapInterface, pcapPath, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    uint32_t pcap{};
    ec = ipmi::getDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapProp, pcap);
    if (ec.value())
    {
        lg2::error("Error in getPcap prop: {ERROR}", "ERROR", ec.message());
        elog<InternalFailure>();
        return std::nullopt;
    }
    return pcap;
}

std::optional<bool> getPcapEnabled(ipmi::Context::ptr& ctx)
{
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, pcapInterface, pcapPath, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    bool pcapEnabled{};
    ec = ipmi::getDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapEnableProp, pcapEnabled);
    if (ec.value())
    {
        lg2::error("Error in getPcap prop");
        elog<InternalFailure>();
        return std::nullopt;
    }
    return pcapEnabled;
}

bool setPcap(ipmi::Context::ptr& ctx, const uint32_t powerCap)
{
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, pcapInterface, pcapPath, service);
    if (ec.value())
    {
        return false;
    }

    ec = ipmi::setDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapProp, powerCap);
    if (ec.value())
    {
        lg2::error("Error in setPcap property: {ERROR}", "ERROR", ec.message());
        elog<InternalFailure>();
        return false;
    }
    return true;
}

bool setPcapEnable(ipmi::Context::ptr& ctx, bool enabled)
{
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, pcapInterface, pcapPath, service);
    if (ec.value())
    {
        return false;
    }

    ec = ipmi::setDbusProperty(ctx, service, pcapPath, pcapInterface,
                               powerCapEnableProp, enabled);
    if (ec.value())
    {
        lg2::error("Error in setPcapEnabled property: {ERROR}", "ERROR",
                   ec.message());
        elog<InternalFailure>();
        return false;
    }
    return true;
}

std::optional<std::string> readAssetTag(ipmi::Context::ptr& ctx)
{
    // Read the object tree with the inventory root to figure out the object
    // that has implemented the Asset tag interface.
    ipmi::DbusObjectInfo objectInfo;
    boost::system::error_code ec = getDbusObject(
        ctx, dcmi::assetTagIntf, ipmi::sensor::inventoryRoot, "", objectInfo);
    if (ec.value())
    {
        return std::nullopt;
    }

    std::string assetTag{};
    ec =
        ipmi::getDbusProperty(ctx, objectInfo.second, objectInfo.first,
                              dcmi::assetTagIntf, dcmi::assetTagProp, assetTag);
    if (ec.value())
    {
        lg2::error("Error in reading asset tag: {ERROR}", "ERROR",
                   ec.message());
        elog<InternalFailure>();
        return std::nullopt;
    }

    return assetTag;
}

bool writeAssetTag(ipmi::Context::ptr& ctx, const std::string& assetTag)
{
    // Read the object tree with the inventory root to figure out the object
    // that has implemented the Asset tag interface.
    ipmi::DbusObjectInfo objectInfo;
    boost::system::error_code ec = getDbusObject(
        ctx, dcmi::assetTagIntf, ipmi::sensor::inventoryRoot, "", objectInfo);
    if (ec.value())
    {
        return false;
    }

    ec =
        ipmi::setDbusProperty(ctx, objectInfo.second, objectInfo.first,
                              dcmi::assetTagIntf, dcmi::assetTagProp, assetTag);
    if (ec.value())
    {
        lg2::error("Error in writing asset tag: {ERROR}", "ERROR",
                   ec.message());
        elog<InternalFailure>();
        return false;
    }
    return true;
}

std::optional<std::string> getHostName(ipmi::Context::ptr& ctx)
{
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, networkConfigIntf, networkConfigObj, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    std::string hostname{};
    ec = ipmi::getDbusProperty(ctx, service, networkConfigObj,
                               networkConfigIntf, hostNameProp, hostname);
    if (ec.value())
    {
        lg2::error("Error fetching hostname");
        elog<InternalFailure>();
        return std::nullopt;
    }
    return hostname;
}

std::optional<EthernetInterface::DHCPConf>
    getDHCPEnabled(ipmi::Context::ptr& ctx)
{
    auto ethdevice = ipmi::getChannelName(ethernetDefaultChannelNum);
    ipmi::DbusObjectInfo ethernetObj{};
    boost::system::error_code ec = ipmi::getDbusObject(
        ctx, ethernetIntf, networkRoot, ethdevice, ethernetObj);
    if (ec.value())
    {
        return std::nullopt;
    }
    std::string service{};
    ec = ipmi::getService(ctx, ethernetIntf, ethernetObj.first, service);
    if (ec.value())
    {
        return std::nullopt;
    }
    std::string dhcpVal{};
    ec = ipmi::getDbusProperty(ctx, service, ethernetObj.first, ethernetIntf,
                               "DHCPEnabled", dhcpVal);
    if (ec.value())
    {
        return std::nullopt;
    }

    return EthernetInterface::convertDHCPConfFromString(dhcpVal);
}

std::optional<bool> getDHCPOption(ipmi::Context::ptr& ctx,
                                  const std::string& prop)
{
    ipmi::ObjectTree objectTree;
    if (ipmi::getAllDbusObjects(ctx, networkRoot, dhcpIntf, objectTree))
    {
        return std::nullopt;
    }

    for (const auto& [path, serviceMap] : objectTree)
    {
        for (const auto& [service, object] : serviceMap)
        {
            bool value{};
            if (ipmi::getDbusProperty(ctx, service, path, dhcpIntf, prop,
                                      value))
            {
                return std::nullopt;
            }

            if (value)
            {
                return true;
            }
        }
    }

    return false;
}

bool setDHCPOption(ipmi::Context::ptr& ctx, std::string prop, bool value)
{
    ipmi::ObjectTree objectTree;
    if (ipmi::getAllDbusObjects(ctx, networkRoot, dhcpIntf, objectTree))
    {
        return false;
    }

    for (const auto& [path, serviceMap] : objectTree)
    {
        for (const auto& [service, object] : serviceMap)
        {
            if (ipmi::setDbusProperty(ctx, service, path, dhcpIntf, prop,
                                      value))
            {
                return false;
            }
        }
    }

    return true;
}

/** @brief To get the value of a specified DHCP vendor option from the D-Bus
 * object tree
 *  @param[in] ctx - context pointer
 *  @param[in] prop - DHCP vendor option property
 *  @returns - std::nullopt if no D-Bus objects
 *           - true if the value is present and non-empty.
 *           - false if the value is present but empty.
 */
std::optional<bool> getDHCPVendorOption(ipmi::Context::ptr& ctx,
                                        const std::string& prop)
{
    ipmi::ObjectTree objectTree;
    if (ipmi::getAllDbusObjects(ctx, networkRoot, dhcpIntf, objectTree))
    {
        return std::nullopt;
    }

    for (const auto& [path, serviceMap] : objectTree)
    {
        for (const auto& [service, object] : serviceMap)
        {
            std::string value;
            if (ipmi::getDbusProperty(ctx, service, path, dhcpIntf, prop,
                                      value))
            {
                return std::nullopt;
            }

            if (!value.empty())
            {
                return true;
            }
        }
    }

    return false;
}

/** @brief To delete the value of a specified DHCP vendor option string from the
 * D-Bus object tree
 *  @param[in] ctx - context pointer
 *  @param[in] option - DHCP vendor option ID
 *  @returns - true if the deletion is successful
 *           - false if no D-Bus objects
 */
bool delVendorOption(ipmi::Context::ptr& ctx, uint32_t option)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    ipmi::ObjectTree objectTree;
    if (ipmi::getAllDbusObjects(ctx, networkRoot, dhcpIntf, objectTree))
    {
        return false;
    }

    for (const auto& [path, serviceMap] : objectTree)
    {
        for (const auto& [service, object] : serviceMap)
        {
            try
            {
                auto method = bus.new_method_call(service.c_str(), path.c_str(),
                                                  dhcpIntf, "DelVendorOption");
                method.append(option);
                bus.call_noreply(method);
            }
            catch (const sdbusplus::exception::SdBusError& ex)
            {
                log<level::ERR>("Failed to invoke SetVendorOption method",
                                entry("ERR=%s", ex.what()));
                elog<InternalFailure>();
            }
        }
    }
    return true;
}

/** @brief To set the value of a specified DHCP vendor option from the D-Bus
 * object tree
 *  @param[in] ctx - context pointer
 *  @param[in] option - DHCP vendor option ID
 *  @param[in] value - DHCP vendor option Value
 *  @returns - true if the setVendorOption is successful
 *           - false if no D-Bus objects
 */
bool setVendorOption(ipmi::Context::ptr& ctx, uint32_t option,
                     std::string value)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    ipmi::ObjectTree objectTree;
    if (ipmi::getAllDbusObjects(ctx, networkRoot, dhcpIntf, objectTree))
    {
        return false;
    }

    for (const auto& [path, serviceMap] : objectTree)
    {
        for (const auto& [service, object] : serviceMap)
        {
            try
            {
                auto method = bus.new_method_call(service.c_str(), path.c_str(),
                                                  dhcpIntf,
                                                  dcmi::dhcpOption43Enabled);
                method.append(option, value);
                bus.call_noreply(method);
            }
            catch (const sdbusplus::exception::SdBusError& ex)
            {
                log<level::ERR>("Failed to invoke SetVendorOption method",
                                entry("ERR=%s", ex.what()));
                elog<InternalFailure>();
            }
        }
    }
    return true;
}

/** @brief To set the value of a specified DHCP vendor class identifier from the
 * D-Bus object tree
 *  @param[in] ctx - context pointer
 *  @param[in] prop - DHCP vendor class identifier property
 *  @param[in] value - DHCP vendor class identifier string
 *  @returns - true if the setVendorClassIdentifier is successful
 *           - false if no D-Bus objects
 */
bool setVendorClassIdentifier(ipmi::Context::ptr& ctx, std::string prop,
                              std::string value)
{
    ipmi::ObjectTree objectTree;
    if (ipmi::getAllDbusObjects(ctx, networkRoot, dhcpIntf, objectTree))
    {
        return false;
    }

    for (const auto& [path, serviceMap] : objectTree)
    {
        size_t pos = path.find_last_of('/');
        if (pos != std::string::npos && path.substr(pos + 1) == "dhcp4")
        {
            for (const auto& [service, object] : serviceMap)
            {
                if (ipmi::setDbusProperty(ctx, service, path, dhcpIntf, prop,
                                          value))
                {
                    return false;
                }
            }
        }
    }

    return true;
}

} // namespace dcmi

constexpr uint8_t exceptionPowerOff = 0x01;
ipmi::RspType<uint16_t, // reserved
              uint8_t,  // exception actions
              uint16_t, // power limit requested in watts
              uint32_t, // correction time in milliseconds
              uint16_t, // reserved
              uint16_t  // statistics sampling period in seconds
              >
    getPowerLimit(ipmi::Context::ptr ctx, uint16_t reserved)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        return ipmi::responseCommandNotAvailable();
    }
    if (reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::optional<uint16_t> pcapValue = dcmi::getPcap(ctx);
    std::optional<bool> pcapEnable = dcmi::getPcapEnabled(ctx);
    if (!pcapValue || !pcapEnable)
    {
        return ipmi::responseUnspecifiedError();
    }

    constexpr uint16_t reserved1{};
    constexpr uint16_t reserved2{};
    /*
     * Exception action if power limit is exceeded and cannot be controlled
     * with the correction time limit is hardcoded to Hard Power Off system
     * and log event to SEL.
     */
    constexpr uint8_t exception = exceptionPowerOff;
    /*
     * Correction time limit and Statistics sampling period is currently not
     * populated.
     */
    constexpr uint32_t correctionTime{};
    constexpr uint16_t statsPeriod{};
    if (*pcapEnable == false)
    {
        constexpr ipmi::Cc responseNoPowerLimitSet = 0x80;
        return ipmi::response(responseNoPowerLimitSet, reserved1, exception,
                              *pcapValue, correctionTime, reserved2,
                              statsPeriod);
    }
    return ipmi::responseSuccess(reserved1, exception, *pcapValue,
                                 correctionTime, reserved2, statsPeriod);
}

ipmi::RspType<> setPowerLimit(ipmi::Context::ptr& ctx, uint16_t reserved1,
                              uint8_t reserved2, uint8_t exceptionAction,
                              uint16_t powerLimit, uint32_t correctionTime,
                              uint16_t reserved3, uint16_t statsPeriod)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        lg2::error("DCMI Power management is unsupported!");
        return ipmi::responseCommandNotAvailable();
    }

    // Only process the power limit requested in watts. Return errors
    // for other fields that are set
    if (reserved1 || reserved2 || reserved3 || correctionTime || statsPeriod ||
        exceptionAction != exceptionPowerOff)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!dcmi::setPcap(ctx, powerLimit))
    {
        return ipmi::responseUnspecifiedError();
    }

    lg2::info("Set Power Cap: {POWERCAP}", "POWERCAP", powerLimit);

    return ipmi::responseSuccess();
}

ipmi::RspType<> applyPowerLimit(ipmi::Context::ptr& ctx, bool enabled,
                                uint7_t reserved1, uint16_t reserved2)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        lg2::error("DCMI Power management is unsupported!");
        return ipmi::responseCommandNotAvailable();
    }
    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!dcmi::setPcapEnable(ctx, enabled))
    {
        return ipmi::responseUnspecifiedError();
    }

    lg2::info("Set Power Cap Enable: {POWERCAPENABLE}", "POWERCAPENABLE",
              enabled);

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t,          // total tag length
              std::vector<char> // tag data
              >
    getAssetTag(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count)
{
    // Verify offset to read and number of bytes to read are not exceeding
    // the range.
    if ((offset > dcmi::assetTagMaxOffset) || (count > dcmi::maxBytes) ||
        ((offset + count) > dcmi::assetTagMaxSize))
    {
        return ipmi::responseParmOutOfRange();
    }

    std::optional<std::string> assetTagResp = dcmi::readAssetTag(ctx);
    if (!assetTagResp)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::string& assetTag = assetTagResp.value();
    // If the asset tag is longer than 63 bytes, restrict it to 63 bytes to
    // suit Get Asset Tag command.
    if (assetTag.size() > dcmi::assetTagMaxSize)
    {
        assetTag.resize(dcmi::assetTagMaxSize);
    }

    if (offset >= assetTag.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    // silently truncate reads beyond the end of assetTag
    if ((offset + count) >= assetTag.size())
    {
        count = assetTag.size() - offset;
    }

    auto totalTagSize = static_cast<uint8_t>(assetTag.size());
    std::vector<char> data{assetTag.begin() + offset,
                           assetTag.begin() + offset + count};

    return ipmi::responseSuccess(totalTagSize, data);
}

ipmi::RspType<uint8_t // new asset tag length
              >
    setAssetTag(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count,
                const std::vector<char>& data)
{
    // Verify offset to read and number of bytes to read are not exceeding
    // the range.
    if ((offset > dcmi::assetTagMaxOffset) || (count > dcmi::maxBytes) ||
        ((offset + count) > dcmi::assetTagMaxSize))
    {
        return ipmi::responseParmOutOfRange();
    }
    if (data.size() != count)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::optional<std::string> assetTagResp = dcmi::readAssetTag(ctx);
    if (!assetTagResp)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::string& assetTag = assetTagResp.value();

    if (offset > assetTag.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    // operation is to truncate at offset and append new data
    assetTag.resize(offset);
    assetTag.append(data.begin(), data.end());

    if (!dcmi::writeAssetTag(ctx, assetTag))
    {
        return ipmi::responseUnspecifiedError();
    }

    auto totalTagSize = static_cast<uint8_t>(assetTag.size());
    return ipmi::responseSuccess(totalTagSize);
}

ipmi::RspType<uint8_t,          // length
              std::vector<char> // data
              >
    getMgmntCtrlIdStr(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count)
{
    if (count > dcmi::maxBytes || offset + count > dcmi::maxCtrlIdStrLen)
    {
        return ipmi::responseParmOutOfRange();
    }

    std::optional<std::string> hostnameResp = dcmi::getHostName(ctx);
    if (!hostnameResp)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::string& hostname = hostnameResp.value();
    // If the id string is longer than 63 bytes, restrict it to 63 bytes to
    // suit set management ctrl str  command.
    if (hostname.size() > dcmi::maxCtrlIdStrLen)
    {
        hostname.resize(dcmi::maxCtrlIdStrLen);
    }

    if (offset >= hostname.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    // silently truncate reads beyond the end of hostname
    if ((offset + count) >= hostname.size())
    {
        count = hostname.size() - offset;
    }

    auto nameSize = static_cast<uint8_t>(hostname.size());
    std::vector<char> data{hostname.begin() + offset,
                           hostname.begin() + offset + count};

    return ipmi::responseSuccess(nameSize, data);
}

ipmi::RspType<uint8_t>
    setMgmntCtrlIdStr(ipmi::Context::ptr& ctx, uint8_t offset, uint8_t count,
                      std::vector<char> data)
{
    if ((offset > dcmi::maxCtrlIdStrLen) || (count > dcmi::maxBytes) ||
        ((offset + count) > dcmi::maxCtrlIdStrLen))
    {
        return ipmi::responseParmOutOfRange();
    }
    if (data.size() != count)
    {
        return ipmi::responseReqDataLenInvalid();
    }
    bool terminalWrite{data.back() == '\0'};
    if (terminalWrite)
    {
        // remove the null termination from the data (no need with std::string)
        data.resize(count - 1);
    }
    else if ((offset + count) == dcmi::maxCtrlIdStrLen)
    {
        return ipmi::responseInvalidCommand();
    }

    static std::string hostname{};
    // read in the current value if not starting at offset 0
    if (hostname.size() == 0 && offset != 0)
    {
        /* read old ctrlIdStr */
        std::optional<std::string> hostnameResp = dcmi::getHostName(ctx);
        if (!hostnameResp)
        {
            return ipmi::responseUnspecifiedError();
        }
        hostname = hostnameResp.value();
        hostname.resize(offset);
    }

    hostname.insert(hostname.begin() + offset, data.begin(),
                    data.begin() + count);
    // do the update if this is the last write
    if (terminalWrite)
    {
        boost::system::error_code ec = ipmi::setDbusProperty(
            ctx, dcmi::networkServiceName, dcmi::networkConfigObj,
            dcmi::networkConfigIntf, dcmi::hostNameProp, hostname);
        hostname.clear();
        if (ec.value())
        {
            return ipmi::responseUnspecifiedError();
        }
    }

    auto totalIdSize = static_cast<uint8_t>(offset + count);
    return ipmi::responseSuccess(totalIdSize);
}

ipmi::RspType<ipmi::message::Payload> getDCMICapabilities(uint8_t parameter)
{
    std::ifstream dcmiCapFile(dcmi::gDCMICapabilitiesConfig);
    if (!dcmiCapFile.is_open())
    {
        lg2::error("DCMI Capabilities file not found");
        return ipmi::responseUnspecifiedError();
    }

    auto data = nlohmann::json::parse(dcmiCapFile, nullptr, false);
    if (data.is_discarded())
    {
        lg2::error("DCMI Capabilities JSON parser failure");
        return ipmi::responseUnspecifiedError();
    }

    constexpr bool reserved1{};
    constexpr uint5_t reserved5{};
    constexpr uint7_t reserved7{};
    constexpr uint8_t reserved8{};
    constexpr uint16_t reserved16{};

    ipmi::message::Payload payload;
    payload.pack(dcmi::specMajorVersion, dcmi::specMinorVersion,
                 dcmi::parameterRevision);

    enum class DCMICapParameters : uint8_t
    {
        SupportedDcmiCaps = 0x01,             // Supported DCMI Capabilities
        MandatoryPlatAttributes = 0x02,       // Mandatory Platform Attributes
        OptionalPlatAttributes = 0x03,        // Optional Platform Attributes
        ManageabilityAccessAttributes = 0x04, // Manageability Access Attributes
    };

    switch (static_cast<DCMICapParameters>(parameter))
    {
        case DCMICapParameters::SupportedDcmiCaps:
        {
            bool powerManagement = data.value("PowerManagement", 0);
            bool oobSecondaryLan = data.value("OOBSecondaryLan", 0);
            bool serialTMode = data.value("SerialTMODE", 0);
            bool inBandSystemInterfaceChannel =
                data.value("InBandSystemInterfaceChannel", 0);
            payload.pack(reserved8, powerManagement, reserved7,
                         inBandSystemInterfaceChannel, serialTMode,
                         oobSecondaryLan, reserved5);
            break;
        }
            // Mandatory Platform Attributes
        case DCMICapParameters::MandatoryPlatAttributes:
        {
            bool selAutoRollOver = data.value("SELAutoRollOver", 0);
            bool flushEntireSELUponRollOver =
                data.value("FlushEntireSELUponRollOver", 0);
            bool recordLevelSELFlushUponRollOver =
                data.value("RecordLevelSELFlushUponRollOver", 0);
            uint12_t numberOfSELEntries =
                data.value("NumberOfSELEntries", 0xcac);
            uint8_t tempMonitoringSamplingFreq =
                data.value("TempMonitoringSamplingFreq", 0);
            payload.pack(numberOfSELEntries, reserved1,
                         recordLevelSELFlushUponRollOver,
                         flushEntireSELUponRollOver, selAutoRollOver,
                         reserved16, tempMonitoringSamplingFreq);
            break;
        }
        // Optional Platform Attributes
        case DCMICapParameters::OptionalPlatAttributes:
        {
            uint7_t powerMgmtDeviceTargetAddress =
                data.value("PowerMgmtDeviceSlaveAddress", 0);
            uint4_t bmcChannelNumber = data.value("BMCChannelNumber", 0);
            uint4_t deviceRivision = data.value("DeviceRivision", 0);
            payload.pack(powerMgmtDeviceTargetAddress, reserved1,
                         deviceRivision, bmcChannelNumber);
            break;
        }
        // Manageability Access Attributes
        case DCMICapParameters::ManageabilityAccessAttributes:
        {
            uint8_t mandatoryPrimaryLanOOBSupport =
                data.value("MandatoryPrimaryLanOOBSupport", 0xff);
            uint8_t optionalSecondaryLanOOBSupport =
                data.value("OptionalSecondaryLanOOBSupport", 0xff);
            uint8_t optionalSerialOOBMTMODECapability =
                data.value("OptionalSerialOOBMTMODECapability", 0xff);
            payload.pack(mandatoryPrimaryLanOOBSupport,
                         optionalSecondaryLanOOBSupport,
                         optionalSerialOOBMTMODECapability);
            break;
        }
        default:
        {
            lg2::error("Invalid input parameter");
            return ipmi::responseInvalidFieldRequest();
        }
    }

    return ipmi::responseSuccess(payload);
}

namespace dcmi
{
namespace temp_readings
{

std::tuple<bool, bool, uint8_t>
    readTemp(ipmi::Context::ptr& ctx, const std::string& dbusService,
             const std::string& dbusPath)
{
    // Read the temperature value from d-bus object. Need some conversion.
    // As per the interface xyz.openbmc_project.Sensor.Value, the
    // temperature is an double and in degrees C. It needs to be scaled by
    // using the formula Value * 10^Scale. The ipmi spec has the temperature
    // as a uint8_t, with a separate single bit for the sign.

    ipmi::PropertyMap result{};
    boost::system::error_code ec = ipmi::getAllDbusProperties(
        ctx, dbusService, dbusPath, "xyz.openbmc_project.Sensor.Value", result);
    if (ec.value())
    {
        return std::make_tuple(false, false, 0);
    }
    auto temperature =
        std::visit(ipmi::VariantToDoubleVisitor(), result.at("Value"));
    double absTemp = std::abs(temperature);

    auto findFactor = result.find("Scale");
    double factor = 0.0;
    if (findFactor != result.end())
    {
        factor = std::visit(ipmi::VariantToDoubleVisitor(), findFactor->second);
    }
    double scale = std::pow(10, factor);

    auto tempDegrees = absTemp * scale;
    // Max absolute temp as per ipmi spec is 127.
    constexpr auto maxTemp = 127;
    if (tempDegrees > maxTemp)
    {
        tempDegrees = maxTemp;
    }

    return std::make_tuple(true, (temperature < 0),
                           static_cast<uint8_t>(tempDegrees));
}

std::tuple<std::vector<std::tuple<uint7_t, bool, uint8_t>>, uint8_t>
    read(ipmi::Context::ptr& ctx, const std::string& type, uint8_t instance,
         size_t count)
{
    std::vector<std::tuple<uint7_t, bool, uint8_t>> response{};

    auto data = parseJSONConfig(gDCMISensorsConfig);
    static const std::vector<nlohmann::json> empty{};
    std::vector<nlohmann::json> readings = data.value(type, empty);

    if (instance == 0)
    {
        instance = instance + 1;
    }
    for (const auto& j : readings)
    {
        // Max of 8 response data sets
        if (response.size() == count)
        {
            break;
        }

        uint8_t instanceNum = j.value("instance", 0);
        // Not in the instance range we're interested in
        if (instanceNum < instance)
        {
            continue;
        }

        std::string path = j.value("dbus", "");
        std::string service{};
        boost::system::error_code ec = ipmi::getService(
            ctx, "xyz.openbmc_project.Sensor.Value", path, service);
        if (ec.value())
        {
            // not found on dbus
            continue;
        }

        const auto& [ok, sign, temp] = readTemp(ctx, service, path);
        if (ok)
        {
            response.emplace_back(uint7_t{temp}, sign, instanceNum);
        }
    }

    auto totalInstances =
        static_cast<uint8_t>(std::min(readings.size(), maxInstances));
    return std::make_tuple(response, totalInstances);
}

} // namespace temp_readings
} // namespace dcmi

ipmi::RspType<uint8_t,                // total instances for entity id
              uint8_t,                // number of instances in this reply
              std::vector<            // zero or more of the following two bytes
                  std::tuple<uint7_t, // temperature value
                             bool,    // sign bit
                             uint8_t  // entity instance
                             >>>
    getTempReadings(ipmi::Context::ptr& ctx, uint8_t sensorType,
                    uint8_t entityId, uint8_t entityInstance,
                    uint8_t instanceStart)
{
    auto it = dcmi::entityIdToName.find(entityId);
    if (it == dcmi::entityIdToName.end())
    {
        lg2::error("Unknown Entity ID: {ENTITY_ID}", "ENTITY_ID", entityId);
        return ipmi::responseInvalidFieldRequest();
    }

    if (sensorType != dcmi::temperatureSensorType)
    {
        lg2::error("Invalid sensor type: {SENSOR_TYPE}", "SENSOR_TYPE",
                   sensorType);
        return ipmi::responseInvalidFieldRequest();
    }

    uint8_t requestedRecords = (entityInstance == 0) ? dcmi::maxRecords : 1;

    // Read requested instances
    const auto& [temps, totalInstances] = dcmi::temp_readings::read(
        ctx, it->second, instanceStart, requestedRecords);

    auto numInstances = static_cast<uint8_t>(temps.size());

    return ipmi::responseSuccess(totalInstances, numInstances, temps);
}

ipmi::RspType<> setDCMIConfParams(ipmi::Context::ptr& ctx, uint8_t parameter,
                                  uint8_t setSelector,
                                  ipmi::message::Payload& payload)
{
    if (setSelector)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    // Take action based on the Parameter Selector
    switch (static_cast<dcmi::DCMIConfigParameters>(parameter))
    {
        case dcmi::DCMIConfigParameters::ActivateDHCP:
        {
            uint7_t reserved{};
            bool activate{};
            if (payload.unpack(activate, reserved) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if (reserved)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::optional<EthernetInterface::DHCPConf> dhcpEnabled =
                dcmi::getDHCPEnabled(ctx);
            if (!dhcpEnabled)
            {
                return ipmi::responseUnspecifiedError();
            }
            if (activate && (dhcpEnabled.value() == EthernetInterface::DHCPConf::v6stateless))
            {
                return ipmi::responseCommandNotAvailable();
            }
            if (activate &&
                (dhcpEnabled.value() != EthernetInterface::DHCPConf::none))
            {
                // When these conditions are met we have to trigger DHCP
                // protocol restart using the latest parameter settings,
                // but as per n/w manager design, each time when we
                // update n/w parameters, n/w service is restarted. So
                // we no need to take any action in this case.
                dcmi::restartSystemdUnit(dcmi::networkdService);
            }
            break;
        }
        case dcmi::DCMIConfigParameters::DiscoveryConfig:
        {
            bool option12{};
            bool option60{};
            uint5_t reserved1{};
            bool randBackOff{};
            constexpr const char* vendorClassID = "DCMI36465:1.5";
            constexpr uint8_t vendorOption1ID = 1;
            constexpr const char* vendorOption1Value = "DCMI";
            constexpr uint8_t vendorOption2ID = 2;
            constexpr const char* vendorOption2Value = "1000";
            constexpr uint8_t vendorOption3ID = 3;
            constexpr const char* vendorOption3Value = "DCMI1.5";
            constexpr uint8_t vendorOption242ID = 242;
            constexpr const char* vendorOption242Value = "AMI";
            if (payload.unpack(option12, option60, reserved1, randBackOff) ||
                !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // Systemd-networkd doesn't support Random Back off
            if (randBackOff)
            {
                return ipmi::responseCommandDisabled();
            }
            if (reserved1)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            if (option60)
            {
                dcmi::setVendorClassIdentifier(ctx, dcmi::dhcpOption60Enabled,
                                               vendorClassID);
                dcmi::setVendorOption(ctx, vendorOption1ID, vendorOption1Value);
                dcmi::setVendorOption(ctx, vendorOption2ID, vendorOption2Value);
                dcmi::setVendorOption(ctx, vendorOption3ID, vendorOption3Value);
                dcmi::setVendorOption(ctx, vendorOption242ID,
                                      vendorOption242Value);
            }
            else
            {
                dcmi::setVendorClassIdentifier(ctx, dcmi::dhcpOption60Enabled,
                                               "");
                dcmi::delVendorOption(ctx, vendorOption1ID);
                dcmi::delVendorOption(ctx, vendorOption2ID);
                dcmi::delVendorOption(ctx, vendorOption3ID);
                dcmi::delVendorOption(ctx, vendorOption242ID);
            }

            dcmi::setDHCPOption(ctx, dcmi::dhcpOpt12Enabled, option12);
            break;
        }
        // Systemd-networkd doesn't allow to configure DHCP timigs
        case dcmi::DCMIConfigParameters::DHCPTiming1:
        case dcmi::DCMIConfigParameters::DHCPTiming2:
        case dcmi::DCMIConfigParameters::DHCPTiming3:
        default:
            return ipmi::responseInvalidCommand();
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<ipmi::message::Payload> getDCMIConfParams(
    ipmi::Context::ptr& ctx, uint8_t parameter, uint8_t setSelector)
{
    if (setSelector)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    ipmi::message::Payload payload;
    payload.pack(dcmi::specMajorVersion, dcmi::specMinorVersion,
                 dcmi::configParameterRevision);

    // Take action based on the Parameter Selector
    switch (static_cast<dcmi::DCMIConfigParameters>(parameter))
    {
        case dcmi::DCMIConfigParameters::ActivateDHCP:
            payload.pack(dcmi::activateDhcpReply);
            break;
        case dcmi::DCMIConfigParameters::DiscoveryConfig:
        {
            uint8_t discovery{};
            std::optional<bool> enabled =
                dcmi::getDHCPOption(ctx, dcmi::dhcpOpt12Enabled);
            std::optional<bool> enabledOption =
                dcmi::getDHCPVendorOption(ctx, dcmi::dhcpOption60Enabled);
            if ((!enabled.has_value()) && (!enabledOption.has_value()))
            {
                return ipmi::responseUnspecifiedError();
            }

            if ((enabled.value()) && (enabledOption.value()))
            {
                discovery = dcmi::option60And12Mask;
            }
            else if (enabled.value())
            {
                discovery = dcmi::option12Mask;
            }
            else if (enabledOption.value())
            {
                discovery = dcmi::option60Mask;
            }

            payload.pack(discovery);
            break;
        }
        // Get below values from Systemd-networkd source code
        case dcmi::DCMIConfigParameters::DHCPTiming1:
            payload.pack(dcmi::dhcpTiming1);
            break;
        case dcmi::DCMIConfigParameters::DHCPTiming2:
            payload.pack(dcmi::dhcpTiming2);
            break;
        case dcmi::DCMIConfigParameters::DHCPTiming3:
            payload.pack(dcmi::dhcpTiming3);
            break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    return ipmi::responseSuccess(payload);
}

static std::optional<uint16_t> readPower(ipmi::Context::ptr& ctx)
{
    std::ifstream sensorFile(POWER_READING_SENSOR);
    std::string objectPath;
    if (!sensorFile.is_open())
    {
        lg2::error(
            "Power reading configuration file not found: {POWER_SENSOR_FILE}",
            "POWER_SENSOR_FILE", std::string_view{POWER_READING_SENSOR});
        return std::nullopt;
    }

    auto data = nlohmann::json::parse(sensorFile, nullptr, false);
    if (data.is_discarded())
    {
        lg2::error("Error in parsing configuration file: {POWER_SENSOR_FILE}",
                   "POWER_SENSOR_FILE", std::string_view{POWER_READING_SENSOR});
        return std::nullopt;
    }

    objectPath = data.value("path", "");
    if (objectPath.empty())
    {
        lg2::error(
            "Power sensor D-Bus object path is empty: {POWER_SENSOR_FILE}",
            "POWER_SENSOR_FILE", std::string_view{POWER_READING_SENSOR});
        return std::nullopt;
    }

    // Return default value if failed to read from D-Bus object
    std::string service{};
    boost::system::error_code ec =
        ipmi::getService(ctx, dcmi::sensorValueIntf, objectPath, service);
    if (ec.value())
    {
        lg2::error("Failed to fetch service for D-Bus object, "
                   "object path: {OBJECT_PATH}, interface: {INTERFACE}",
                   "OBJECT_PATH", objectPath, "INTERFACE",
                   dcmi::sensorValueIntf);
        return std::nullopt;
    }

    // Read the sensor value and scale properties
    double value{};
    ec = ipmi::getDbusProperty(ctx, service, objectPath, dcmi::sensorValueIntf,
                               dcmi::sensorValueProp, value);
    if (ec.value())
    {
        lg2::error("Failed to read power value from D-Bus object, "
                   "object path: {OBJECT_PATH}, interface: {INTERFACE}",
                   "OBJECT_PATH", objectPath, "INTERFACE",
                   dcmi::sensorValueIntf);
        return std::nullopt;
    }
    auto power = static_cast<uint16_t>(value);
    return power;
}

ipmi::RspType<uint16_t, // current power
              uint16_t, // minimum power
              uint16_t, // maximum power
              uint16_t, // average power
              uint32_t, // timestamp
              uint32_t, // sample period ms
              uint6_t,  // reserved
              bool,     // power measurement active
              bool      // reserved
              >
    getPowerReading(ipmi::Context::ptr& ctx, uint8_t mode, uint8_t attributes,
                    uint8_t reserved)
{
    if (!dcmi::isDCMIPowerMgmtSupported())
    {
        lg2::error("DCMI Power management is unsupported!");
        return ipmi::responseCommandNotAvailable();
    }
    if (reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    enum class PowerMode : uint8_t
    {
        SystemPowerStatistics = 1,
        EnhancedSystemPowerStatistics = 2,
    };

    if (static_cast<PowerMode>(mode) != PowerMode::SystemPowerStatistics)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if (attributes)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::optional<uint16_t> powerResp = readPower(ctx);
    if (!powerResp)
    {
        return ipmi::responseUnspecifiedError();
    }
    auto& power = powerResp.value();

    // TODO: openbmc/openbmc#2819
    // Minimum, Maximum, Average power, TimeFrame, TimeStamp,
    // PowerReadingState readings need to be populated
    // after Telemetry changes.
    constexpr uint32_t samplePeriod = 1;
    constexpr uint6_t reserved1 = 0;
    constexpr bool measurementActive = true;
    constexpr bool reserved2 = false;
    auto timestamp = static_cast<uint32_t>(time(nullptr));
    return ipmi::responseSuccess(power, power, power, power, timestamp,
                                 samplePeriod, reserved1, measurementActive,
                                 reserved2);
}

ipmi::RspType<uint8_t, uint8_t, uint16_t>
    getThermalLimit(uint8_t getThermalEntityID,
                    uint8_t GetThermalEntityInstance)

{
    uint8_t getTempLimit;
    uint8_t getExceptime;
    uint8_t getExceptAct = 0;
    std::map<uint8_t, std::string>::const_iterator it;

    if ((getThermalEntityID != inletTemp1) &&
        (getThermalEntityID != inletTemp2))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (GetThermalEntityInstance != entyInstance)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // GET EXCEPTION ACTION value from Dbus.
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto value = ipmi::getDbusProperty(
            *dbus, dcmi::thermalBus, dcmi::thermalLimitObjpath,
            dcmi::thermalLimitIntf, "ExceptionAction");
        for (it = dcmi::thermalmap.begin(); it != dcmi::thermalmap.end(); ++it)
        {
            if (it->second == std::get<std::string>(value))
            {
                getExceptAct = it->first;
                break;
            }
        }
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to Get Thermal ExceptionAction : {ERROR}", "ERROR",
                   e);
        return ipmi::responseUnspecifiedError();
    }
    // GET TEMPRATURE LIMIT value from Dbus.
    try
    {
        auto value = ipmi::getDbusProperty(
            *dbus, dcmi::thermalBus, dcmi::thermalLimitObjpath,
            dcmi::thermalLimitIntf, "TemparatureLimit");
        getTempLimit = std::get<uint8_t>(value);
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to Get Thermal TemparatureLimit : {ERROR}", "ERROR",
                   e);
        return ipmi::responseUnspecifiedError();
    }
    // GET EXCEPTION TIME value from Dbus.
    try
    {
        auto value = ipmi::getDbusProperty(
            *dbus, dcmi::thermalBus, dcmi::thermalLimitObjpath,
            dcmi::thermalLimitIntf, "ExceptionTime");
        getExceptime = std::get<uint16_t>(value);
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to Get Thermal ExceptionTime : {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(getExceptAct, getTempLimit, getExceptime);
}

ipmi::RspType<> setThermalLimit(uint8_t thermalEntityID,
                                uint8_t thermalEntityInstance,
                                uint8_t thermalExceptionAction,
                                uint8_t tempLimit, uint16_t exceptionTime)
{
    if ((thermalEntityID != inletTemp1) && (thermalEntityID != inletTemp2))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (thermalEntityInstance != entyInstance)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if ((thermalExceptionAction != loggingSEL) &&
        (thermalExceptionAction != hardPowerOff) &&
        (thermalExceptionAction != exceptionAction2))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto thermalItr = dcmi::thermalmap.find(thermalExceptionAction);
    if (thermalItr == dcmi::thermalmap.end())
    {
        return ipmi::responseInvalidFieldRequest();
    }
    std::string thermalString = thermalItr->second;
    // Setting Exception Action value to dbus
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        ipmi::setDbusProperty(*dbus, dcmi::thermalBus,
                              dcmi::thermalLimitObjpath, dcmi::thermalLimitIntf,
                              "ExceptionAction", thermalString.c_str());
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to set Thermal ExceptionAction : {ERROR}", "ERROR",
                   e);
        return ipmi::responseUnspecifiedError();
    }
    // Setting Temparature Limit value to dbus
    try
    {
        ipmi::setDbusProperty(*dbus, dcmi::thermalBus,
                              dcmi::thermalLimitObjpath, dcmi::thermalLimitIntf,
                              "TemparatureLimit", tempLimit);
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to set Thermal TemparatureLimit : {ERROR}", "ERROR",
                   e);
        return ipmi::responseUnspecifiedError();
    }
    // Setting Exception Time value to dbus
    try
    {
        ipmi::setDbusProperty(*dbus, dcmi::thermalBus,
                              dcmi::thermalLimitObjpath, dcmi::thermalLimitIntf,
                              "ExceptionTime", exceptionTime);
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to set Thermal ExceptionTime : {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

namespace dcmi
{
namespace sensor_info
{

std::tuple<std::vector<uint16_t>, uint8_t>
    read(const std::string& type, uint8_t instance,
         const nlohmann::json& config, uint8_t count)
{
    std::vector<uint16_t> responses{};

    static const std::vector<nlohmann::json> empty{};
    std::vector<nlohmann::json> readings = config.value(type, empty);
    uint8_t totalInstances = std::min(readings.size(), maxInstances);
    for (const auto& reading : readings)
    {
        // limit to requested count
        if (responses.size() == count)
        {
            break;
        }

        uint8_t instanceNum = reading.value("instance", 0);
        // Not in the instance range we're interested in
        if (instanceNum < instance)
        {
            continue;
        }

        uint16_t recordId = reading.value("record_id", 0);
        responses.emplace_back(recordId);
    }

    return std::make_tuple(responses, totalInstances);
}

} // namespace sensor_info
} // namespace dcmi

ipmi::RspType<uint8_t,              // total available instances
              uint8_t,              // number of records in this response
              std::vector<uint16_t> // records
              >
    getSensorInfo(uint8_t sensorType, uint8_t entityId, uint8_t entityInstance,
                  uint8_t instanceStart)
{
    auto it = dcmi::entityIdToName.find(entityId);
    if (it == dcmi::entityIdToName.end())
    {
        lg2::error("Unknown Entity ID: {ENTITY_ID}", "ENTITY_ID", entityId);
        return ipmi::responseInvalidFieldRequest();
    }

    if (sensorType != dcmi::temperatureSensorType)
    {
        lg2::error("Invalid sensor type: {SENSOR_TYPE}", "SENSOR_TYPE",
                   sensorType);
        return ipmi::responseInvalidFieldRequest();
    }

    nlohmann::json config = dcmi::parseJSONConfig(dcmi::gDCMISensorsConfig);

    uint8_t requestedRecords = (entityInstance == 0) ? dcmi::maxRecords : 1;
    // Read requested instances
    const auto& [sensors, totalInstances] = dcmi::sensor_info::read(
        it->second, instanceStart, config, requestedRecords);
    uint8_t numRecords = sensors.size();

    return ipmi::responseSuccess(totalInstances, numRecords, sensors);
}

void register_netfn_dcmi_functions()
{
    // <Get Power Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetPowerLimit, ipmi::Privilege::User,
                         getPowerLimit);

    // <Set Power Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetPowerLimit,
                         ipmi::Privilege::Operator, setPowerLimit);

    // <Activate/Deactivate Power Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdActDeactivatePwrLimit,
                         ipmi::Privilege::Operator, applyPowerLimit);

    // <Get Asset Tag>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetAssetTag, ipmi::Privilege::User,
                         getAssetTag);

    // <Set Asset Tag>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetAssetTag, ipmi::Privilege::Operator,
                         setAssetTag);

    // <Get Management Controller Identifier String>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetMgmtCntlrIdString,
                         ipmi::Privilege::User, getMgmntCtrlIdStr);

    // <Set Management Controller Identifier String>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetMgmtCntlrIdString,
                         ipmi::Privilege::Admin, setMgmntCtrlIdStr);

    // <Get DCMI capabilities>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetDcmiCapabilitiesInfo,
                         ipmi::Privilege::User, getDCMICapabilities);

    // <Get Power Reading>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetPowerReading, ipmi::Privilege::User,
                         getPowerReading);
    // <Set Thermal Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetThermalLimit, ipmi::Privilege::User,
                         setThermalLimit);
    // <Get Thermal Limit>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetThermalLimit, ipmi::Privilege::User,
                         getThermalLimit);

// The Get sensor should get the senor details dynamically when
// FEATURE_DYNAMIC_SENSORS is enabled.
#ifndef FEATURE_DYNAMIC_SENSORS
    // <Get Sensor Info>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetDcmiSensorInfo,
                         ipmi::Privilege::Operator, getSensorInfo);

    // <Get Temperature Readings>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetTemperatureReadings,
                         ipmi::Privilege::User, getTempReadings);
#endif
    // <Get DCMI Configuration Parameters>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdGetDcmiConfigParameters,
                         ipmi::Privilege::User, getDCMIConfParams);

    // <Set DCMI Configuration Parameters>
    registerGroupHandler(ipmi::prioOpenBmcBase, ipmi::groupDCMI,
                         ipmi::dcmi::cmdSetDcmiConfigParameters,
                         ipmi::Privilege::Admin, setDCMIConfParams);

    return;
}
