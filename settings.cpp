#include "settings.hpp"

#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message/types.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/ObjectMapper/common.hpp>

using ObjectMapper = sdbusplus::common::xyz::openbmc_project::ObjectMapper;

namespace settings
{

using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;

Objects::Objects(sdbusplus::bus_t& bus, const std::vector<Interface>& filter) :
    bus(bus)
{
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree = ipmi::getSubTree(bus, filter);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to call the getSubTree method: {ERROR}", "ERROR", e);
        elog<InternalFailure>();
    }

    for (auto& iter : objectTree)
    {
        const auto& path = iter.first;
        if (!serviceMap.contains(path))
        {
            serviceMap.emplace(path, iter.second.begin()->first);
        }

        for (auto& interface : iter.second.begin()->second)
        {
            auto found = map.find(interface);
            if (map.end() != found)
            {
                auto& paths = found->second;
                paths.push_back(path);
            }
            else
            {
                map.emplace(std::move(interface), std::vector<Path>({path}));
            }
        }
    }
}

Service Objects::service(const Path& path, const Interface& interface) const
{
    using Interfaces = std::vector<Interface>;
    auto mapperCall = bus.new_method_call(
        ObjectMapper::default_service, ObjectMapper::instance_path,
        ObjectMapper::interface, "GetObject");
    mapperCall.append(path);
    mapperCall.append(Interfaces({interface}));

    std::map<Service, Interfaces> result;
    try
    {
        auto response = bus.call(mapperCall);
        response.read(result);
        return result.begin()->first;
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid response from mapper: {ERROR}", "ERROR", e);
        elog<InternalFailure>();
    }
}

namespace boot
{

std::tuple<Path, OneTimeEnabled> setting(const Objects& objects,
                                         const Interface& iface)
{
    constexpr auto bootObjCount = 2;
    constexpr auto oneTime = "one_time";
    constexpr auto enabledIntf = "xyz.openbmc_project.Object.Enable";

    const std::vector<Path>& paths = objects.map.at(iface);
    auto count = paths.size();
    if (count != bootObjCount)
    {
        log<level::ERR>("Exactly two objects expected",
                        entry("INTERFACE=%s", iface.c_str()),
                        entry("COUNT=%d", count));
        elog<InternalFailure>();
    }
    size_t index = 0;
    if (std::string::npos == paths[0].rfind(oneTime))
    {
        index = 1;
    }
    const Path& oneTimeSetting = paths[index];
    const Path& regularSetting = paths[!index];

    auto method = objects.bus.new_method_call(
        objects.service(oneTimeSetting, iface).c_str(), oneTimeSetting.c_str(),
        ipmi::PROP_INTF, "Get");
    method.append(enabledIntf, "Enabled");
    auto reply = objects.bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in getting Enabled property",
                        entry("OBJECT=%s", oneTimeSetting.c_str()),
                        entry("INTERFACE=%s", iface.c_str()));
        elog<InternalFailure>();
    }

    std::variant<bool> enabled;
    reply.read(enabled);
    auto oneTimeEnabled = std::get<bool>(enabled);
    const Path& setting = oneTimeEnabled ? oneTimeSetting : regularSetting;
    return std::make_tuple(setting, oneTimeEnabled);
}

} // namespace boot

} // namespace settings
