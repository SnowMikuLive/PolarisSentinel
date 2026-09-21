using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

public interface IPolicyEngine
{
    // 评估检测结果，返回带决策字段的告警
    // Evaluate a detection and return the alert enriched with the decision
    Alert Evaluate(Alert result);

    //Reloads the current policy configuration
    Task RefreshSettingsAsync();

    // 用已有告警的最大编号初始化计数器，避免重启后 ID 冲突
    // Seed the alert counter from existing alerts so ids do not collide after a restart
    void InitializeAlertCounter(int maxExistingNumber);
}
