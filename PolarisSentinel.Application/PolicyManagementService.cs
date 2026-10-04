using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Application;

// Application use case for policy management: validates policy invariants and assigns
// the next sequential id. Controllers delegate here instead of embedding domain rules.
public class PolicyManagementService
{
    private readonly IUnitOfWork _unitOfWork;

    public PolicyManagementService(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    // Validates the policy fields against the ranges the policy engine relies on.
    // Returns the validation errors keyed by field.
    public IReadOnlyDictionary<string, string> Validate(Policy policy)
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

        return errors;
    }

    // Next "P-n" id, scanned from the stored policies.
    public async Task<string> NextPolicyIdAsync(CancellationToken cancellationToken = default)
    {
        var policies = await _unitOfWork.Policies.GetAllAsync(cancellationToken);
        int max = EntityIds.MaxNumber(policies.Select(p => p.Id), EntityIds.PolicyPrefix);
        return $"{EntityIds.PolicyPrefix}{max + 1}";
    }
}
