#include "globalhandler.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

static std::atomic_flag reset_queued = ATOMIC_FLAG_INIT;
static constexpr auto bmcStateRoot = "/xyz/openbmc_project/state";
static constexpr auto bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr auto reqTransition = "RequestedBMCTransition";
static constexpr auto match = "bmc0";

constexpr auto SYSTEMD_SERVICE = "org.freedesktop.systemd1";
constexpr auto SYSTEMD_OBJ_PATH = "/org/freedesktop/systemd1";
constexpr auto SYSTEMD_INTERFACE = "org.freedesktop.systemd1.Manager";
constexpr auto SYSTEMD_WARM_RESET_TARGET = "phosphor-ipmi-warm-reset.target";

using namespace phosphor::logging;
using BMC = sdbusplus::server::xyz::openbmc_project::state::BMC;

void register_netfn_global_functions() __attribute__((constructor));

void resetBMC()
{
    sdbusplus::bus_t bus{ipmid_get_sd_bus_connection()};

    auto bmcStateObj =
        ipmi::getDbusObject(bus, bmcStateIntf, bmcStateRoot, match);

    auto service = ipmi::getService(bus, bmcStateIntf, bmcStateObj.first);

    ipmi::setDbusProperty(bus, service, bmcStateObj.first, bmcStateIntf,
                          reqTransition,
                          convertForMessage(BMC::Transition::Reboot));
}

/** @brief implements cold reset commands
 *    @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiColdReset()
{
    try
    {
        resetBMC();
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception in Global Reset: {ERROR}", "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }

    // Status code.
    return ipmi::responseSuccess();
}

void warmResetBMC()
{
    try
    {
        std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
        // Reset the failed units so we don't end up having systemd
        // not properly restart if the command is spammed.
        busp->async_method_call(
            [](boost::system::error_code ec) {
                if (ec)
                {
                    log<level::ERR>("Error in warm reset");
                }
                return;
            },
            SYSTEMD_SERVICE, SYSTEMD_OBJ_PATH, SYSTEMD_INTERFACE,
            "ResetFailed");
        // Restart the target (restart will propagate to units).
        busp->async_method_call(
            [](boost::system::error_code ec) {
                if (ec)
                {
                    log<level::ERR>("Error in warm reset");
                }
                return;
            },
            SYSTEMD_SERVICE, SYSTEMD_OBJ_PATH, SYSTEMD_INTERFACE, "RestartUnit",
            SYSTEMD_WARM_RESET_TARGET, "replace");
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }
}

/** @brief implements warm reset command
 *  @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiWarmReset()
{
    try
    {
        if (!reset_queued.test_and_set())
        {
            // Do this asynchronously so that we can properly return this
            // command.
            std::thread t(warmResetBMC);
            t.detach();
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        reset_queued.clear();
        return ipmi::responseUnspecifiedError();
    }

    // Status code.
    return ipmi::responseSuccess();
}

void register_netfn_global_functions()
{
    // Cold Reset
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdColdReset, ipmi::Privilege::Admin,
                          ipmiColdReset);

    // Warm Reset
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdWarmReset, ipmi::Privilege::Admin,
                          ipmiWarmReset);
    return;
}
