#include <PDKHooks.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

static std::atomic_flag reset_queued = ATOMIC_FLAG_INIT;

constexpr auto SYSTEMD_SERVICE = "org.freedesktop.systemd1";
constexpr auto SYSTEMD_OBJ_PATH = "/org/freedesktop/systemd1";
constexpr auto SYSTEMD_INTERFACE = "org.freedesktop.systemd1.Manager";
constexpr auto SYSTEMD_WARM_RESET_TARGET = "phosphor-ipmi-warm-reset.target";

using BMCState = sdbusplus::server::xyz::openbmc_project::state::BMC;

void registerNetFnGlobalFunctions() __attribute__((constructor));

/** @brief implements cold reset commands
 *    @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiColdReset(ipmi::Context::ptr ctx)
{
    PDK_BMCColdReset();
    ipmi::DbusObjectInfo bmcStateObj;
    boost::system::error_code ec = ipmi::getDbusObject(
        ctx, BMCState::interface, BMCState::namespace_path::value,
        BMCState::namespace_path::bmc, bmcStateObj);
    if (!ec)
    {
        std::string service;
        ec = ipmi::getService(ctx, BMCState::interface, bmcStateObj.first,
                              service);
        if (!ec)
        {
            ec = ipmi::setDbusProperty(
                ctx, service, bmcStateObj.first, BMCState::interface,
                BMCState::property_names::requested_bmc_transition,
                convertForMessage(BMCState::Transition::Reboot));
        }
    }
    if (ec)
    {
        lg2::error("Exception in Cold Reset: {ERROR}", "ERROR", ec.what());
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
                    lg2::error("Error in warm reset");
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
                    lg2::error("Error in warm reset");
                }
                return;
            },
            SYSTEMD_SERVICE, SYSTEMD_OBJ_PATH, SYSTEMD_INTERFACE, "RestartUnit",
            SYSTEMD_WARM_RESET_TARGET, "replace");
    }
    catch (std::exception& e)
    {
        lg2::error("Exception in warm Reset: {ERROR}", "ERROR", e.what());
    }
}

/** @brief implements warm reset command
 *  @param - None
 *  @returns IPMI completion code.
 */
ipmi::RspType<> ipmiWarmReset()
{
    PDK_BMCWarmReset();
    try
    {
        if (reset_queued.test_and_set())
        {
            return ipmi::responseCommandNotAvailable();
        }
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            try
            {
                warmResetBMC();
            }
            catch (const std::exception& ex)
            {
                lg2::error("Exception in ipmi warm Reset: {ERROR}", "ERROR",
                           ex.what());
                reset_queued.clear();
            }
        }).detach();
    }
    catch (std::exception& e)
    {
        lg2::error("Exception in ipmi warm Reset: {ERROR}", "ERROR", e.what());
        reset_queued.clear();
        return ipmi::responseUnspecifiedError();
    }

    // Status code.
    return ipmi::responseSuccess();
}

void registerNetFnGlobalFunctions()
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
