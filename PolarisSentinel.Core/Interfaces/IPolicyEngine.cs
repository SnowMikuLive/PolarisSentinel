using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

//策略引擎契约：评估告警并写回Action/Reason等决策字段。
//Policy engine contract:evaluate an alert and apply decision fields.
public interface IPolicyEngine
{
    //对指定策略评估一条告警（同一Alert实例被就地更新）。
    //Evaluate one alert against a policy (mutates the same instance).
    Alert Evaluate(Alert alert, Policy policy);

}
