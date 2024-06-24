#include "config.h"

#include "systemintfcmds.hpp"

#include "host-cmd-manager.hpp"
#include "host-interface.hpp"

#include <ipmid-host/cmd.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>

#include <bitset>
#include <cstring>
#include <fstream>
void register_netfn_app_functions() __attribute__((constructor));

/*D-bus details for BMC Global enable */
static constexpr const char* settingService = "xyz.openbmc_project.Settings";
static constexpr const char* globalEnblObjpath =
    "/xyz/openbmc_project/control/globalenables";
static constexpr const char* globalEnblInterface =
    "xyz.openbmc_project.Control.BMC.Globalenables";

static bool enable = true;
static bool disable = false;

enum class BMCGlobalEnable : uint8_t
{
    recvMsgQueueInterrupt = 0,
    eventMsgFullIntr = 1,
    eventMsgBuf = 2,
    sel = 3,
    reserved = 4,
    oem0 = 5,
    oem1 = 6,
    oem2 = 7
};

using namespace sdbusplus::server::xyz::openbmc_project::control;

// For accessing Host command manager
using cmdManagerPtr = std::unique_ptr<phosphor::host::command::Manager>;
extern cmdManagerPtr& ipmid_get_host_cmd_manager();

//-------------------------------------------------------------------
// Called by Host post response from Get_Message_Flags
//-------------------------------------------------------------------
ipmi::RspType<uint16_t,              // id
              uint8_t,               // type
              uint24_t,              //  manuf_id
              uint32_t,              // timestamp
              uint8_t,               // netfun
              uint8_t,               // cmd
              std::array<uint8_t, 4> // data
              >
    ipmiAppReadEventBuffer(ipmi::Context::ptr& ctx)
{
    // require this to be limited to system interface
    if (ctx->channel != ipmi::channelSystemIface)
    {
        return ipmi::responseInvalidCommand();
    }

    constexpr uint16_t selOemId = 0x5555;
    constexpr uint8_t selRecordTypeOem = 0xc0;

    // read manufacturer ID from dev_id file
    static uint24_t manufId{};
    if (!manufId)
    {
        const char* filename = "/usr/share/ipmi-providers/dev_id.json";
        std::ifstream devIdFile(filename);
        if (devIdFile.is_open())
        {
            auto data = nlohmann::json::parse(devIdFile, nullptr, false);
            if (!data.is_discarded())
            {
                manufId = data.value("manuf_id", 0);
            }
        }
    }

    constexpr uint32_t timestamp{0};

    // per IPMI spec NetFuntion for OEM
    constexpr uint8_t netfun = 0x3a;

    // Read from the Command Manager queue. What gets returned is a
    // pair of <command, data> that can be directly used here
    const auto& [cmd, data0] = ipmid_get_host_cmd_manager()->getNextCommand();
    constexpr uint8_t dataUnused = 0xff;

    return ipmi::responseSuccess(
        selOemId, selRecordTypeOem, manufId, timestamp, netfun, cmd,
        std::to_array<uint8_t>({data0, dataUnused, dataUnused, dataUnused}));
}

//---------------------------------------------------------------------
// Called by Host on seeing a SMS_ATN bit set. Return a hardcoded
// value of 0x0 to indicate Event Message Buffer is not supported
//-------------------------------------------------------------------
ipmi::RspType<uint8_t> ipmiAppGetMessageFlags()
{
    // From IPMI spec V2.0 for Get Message Flags Command :
    // bit:[1] from LSB : 1b = Event Message Buffer Full.
    // Return as 0 if Event Message Buffer is not supported,
    // or when the Event Message buffer is disabled.
    // This path is used to communicate messages to the host
    // from within the phosphor::host::command::Manager
    constexpr uint8_t setEventMsgBufferNotSupported = 0x0;
    return ipmi::responseSuccess(setEventMsgBufferNotSupported);
}

ipmi::RspType<uint8_t> ipmiAppGetBMCGlobalEnable()
{
    uint8_t globalEnables = 0;
    try
    {
        sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

        ipmi::Value propValue =
            ipmi::getDbusProperty(bus, settingService, globalEnblObjpath,
                                  globalEnblInterface, "RecvMsgQueueInterrupt");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |= (1 << static_cast<uint8_t>(
                                  BMCGlobalEnable::recvMsgQueueInterrupt));
        }

        propValue =
            ipmi::getDbusProperty(bus, settingService, globalEnblObjpath,
                                  globalEnblInterface, "EventmsgFullintr");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |=
                (1 << static_cast<uint8_t>(BMCGlobalEnable::eventMsgFullIntr));
        }

        propValue = ipmi::getDbusProperty(bus, settingService,
                                          globalEnblObjpath,
                                          globalEnblInterface, "EventmsgBuf");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |=
                (1 << static_cast<uint8_t>(BMCGlobalEnable::eventMsgBuf));
        }

        propValue = ipmi::getDbusProperty(
            bus, settingService, globalEnblObjpath, globalEnblInterface, "Sel");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |= (1 << static_cast<uint8_t>(BMCGlobalEnable::sel));
        }

        propValue = ipmi::getDbusProperty(bus, settingService,
                                          globalEnblObjpath,
                                          globalEnblInterface, "OEM0");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |= (1 << static_cast<uint8_t>(BMCGlobalEnable::oem0));
        }

        propValue = ipmi::getDbusProperty(bus, settingService,
                                          globalEnblObjpath,
                                          globalEnblInterface, "OEM1");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |= (1 << static_cast<uint8_t>(BMCGlobalEnable::oem1));
        }

        propValue = ipmi::getDbusProperty(bus, settingService,
                                          globalEnblObjpath,
                                          globalEnblInterface, "OEM2");
        if (std::holds_alternative<bool>(propValue) &&
            std::get<bool>(propValue))
        {
            globalEnables |= (1 << static_cast<uint8_t>(BMCGlobalEnable::oem2));
        }
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get BMC Global Enables",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess(globalEnables);
}

ipmi::RspType<> ipmiAppSetBMCGlobalEnable(ipmi::Context::ptr ctx,
                                          uint8_t globalEnables)
{
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Channel Info",
            phosphor::logging::entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }

    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error - supported only in system interface");
        return ipmi::responseCommandNotAvailable();
    }

    if (globalEnables & (1 << static_cast<uint8_t>(BMCGlobalEnable::reserved)))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

    // Process each global enable bit and set the corresponding D-Bus property
    ipmi::setDbusProperty(bus, settingService, globalEnblObjpath,
                          globalEnblInterface, "RecvMsgQueueInterrupt",
                          globalEnables &
                                  (1 << static_cast<uint8_t>(
                                       BMCGlobalEnable::recvMsgQueueInterrupt))
                              ? enable
                              : disable);

    ipmi::setDbusProperty(
        bus, settingService, globalEnblObjpath, globalEnblInterface,
        "EventmsgFullintr",
        globalEnables &
                (1 << static_cast<uint8_t>(BMCGlobalEnable::eventMsgFullIntr))
            ? enable
            : disable);

    ipmi::setDbusProperty(bus, settingService, globalEnblObjpath,
                          globalEnblInterface, "EventmsgBuf",
                          globalEnables & (1 << static_cast<uint8_t>(
                                               BMCGlobalEnable::eventMsgBuf))
                              ? enable
                              : disable);

    ipmi::setDbusProperty(
        bus, settingService, globalEnblObjpath, globalEnblInterface, "Sel",
        globalEnables & (1 << static_cast<uint8_t>(BMCGlobalEnable::sel))
            ? enable
            : disable);

    ipmi::setDbusProperty(
        bus, settingService, globalEnblObjpath, globalEnblInterface, "OEM0",
        globalEnables & (1 << static_cast<uint8_t>(BMCGlobalEnable::oem0))
            ? enable
            : disable);

    ipmi::setDbusProperty(
        bus, settingService, globalEnblObjpath, globalEnblInterface, "OEM1",
        globalEnables & (1 << static_cast<uint8_t>(BMCGlobalEnable::oem1))
            ? enable
            : disable);

    ipmi::setDbusProperty(
        bus, settingService, globalEnblObjpath, globalEnblInterface, "OEM2",
        globalEnables & (1 << static_cast<uint8_t>(BMCGlobalEnable::oem2))
            ? enable
            : disable);

    return ipmi::responseSuccess();
}

namespace
{
// Static storage to keep the object alive during process life
std::unique_ptr<phosphor::host::command::Host> host
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::server::manager_t> objManager
    __attribute__((init_priority(101)));
} // namespace

void register_netfn_app_functions()
{
    // <Read Event Message Buffer>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdReadEventMessageBuffer,
                          ipmi::Privilege::Admin, ipmiAppReadEventBuffer);

    // <Set BMC Global Enables>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdSetBmcGlobalEnables,
                          ipmi::Privilege::Admin, ipmiAppSetBMCGlobalEnable);

    // <Get BMC Global Enables>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetBmcGlobalEnables,
                          ipmi::Privilege::User, ipmiAppGetBMCGlobalEnable);

    // <Get Message Flags>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessageFlags, ipmi::Privilege::Admin,
                          ipmiAppGetMessageFlags);

    // Create new xyz.openbmc_project.host object on the bus
    auto objPath = std::string{CONTROL_HOST_OBJ_MGR} + '/' + HOST_NAME + '0';

    std::unique_ptr<sdbusplus::asio::connection>& sdbusp =
        ipmid_get_sdbus_plus_handler();

    // Add sdbusplus ObjectManager.
    objManager = std::make_unique<sdbusplus::server::manager_t>(
        *sdbusp, CONTROL_HOST_OBJ_MGR);

    host = std::make_unique<phosphor::host::command::Host>(*sdbusp,
                                                           objPath.c_str());
    sdbusp->request_name(CONTROL_HOST_BUSNAME);

    return;
}
