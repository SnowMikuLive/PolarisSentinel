using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

public class PolicyManagementService
{
    private readonly IUnitOfWork _unitOfWork;

    public PolicyManagementService(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    public static IReadOnlyDictionary<string, string> Validate(Policy policy)
    {
        var errors = new Dictionary<string, string>();

        if (string.IsNullOrWhiteSpace(policy.Name))
        {
            errors[nameof(Policy.Name)] = "Name is required.";
        }

        if (policy.Priority is < 0 or > 100)
        {
            errors[nameof(Policy.Priority)] = "Priority must be between 0 and 100.";
        }

        if (policy.RfThreshold is { } rf && (rf < 0 || rf > 1))
        {
            errors[nameof(Policy.RfThreshold)] = "RF threshold must be between 0 and 1.";
        }

        if (policy.IfThreshold is { } ift && (ift < 0 || ift > 1))
        {
            errors[nameof(Policy.IfThreshold)] = "IF threshold must be between 0 and 1.";
        }

        if (PolicyActions.IsBlocking(policy.Action) && policy.BlockDurationMinutes <= 0)
        {
            errors[nameof(Policy.BlockDurationMinutes)] = "Block duration must be positive for blocking policies.";
        }

        if (!string.IsNullOrWhiteSpace(policy.AttackType) && !AttackTypes.IsDefined(policy.AttackType))
        {
            errors[nameof(Policy.AttackType)] = "Unknown attack type.";
        }

        if (string.Equals(policy.AttackType, AttackTypes.UnknownAnomaly, StringComparison.OrdinalIgnoreCase) &&
            PolicyActions.IsBlocking(policy.Action))
        {
            errors[nameof(Policy.AttackType)] = "Unknown anomalies are monitor-only; choose a monitor action or a named attack type.";
        }

        return errors;
    }

    public async Task<string> NextPolicyIdAsync(CancellationToken cancellationToken = default)
    {
        var policies = await _unitOfWork.Policies.GetAllAsync(cancellationToken);
        int max = EntityIds.MaxNumber(policies.Select(p => p.Id), EntityIds.PolicyPrefix);
        return $"{EntityIds.PolicyPrefix}{EntityIds.ReserveNextNumber(max, EntityIds.PolicyPrefix)}";
    }
}
