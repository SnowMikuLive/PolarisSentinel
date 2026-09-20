using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Core.Interfaces;

// 应用层检测管线接口
// Application-layer detection pipeline contract
public interface IDetectionPipeline
{
    Policy ProcessFlow(FlowFeatureVector flow);
}
