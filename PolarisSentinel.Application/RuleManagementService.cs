using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentinel.Application;

public class RuleManagementService
{
    private readonly IFirewallEnforcer _firewall;
    private readonly IUnitOfWork _unitOfWork;

    public RuleManagementService(IFirewallEnforcer firewall, IUnitOfWork unitOfWork)
    {
        _firewall = firewall;
        _unitOfWork = unitOfWork;
    }

    public static IReadOnlyDictionary<string, string> Validate(Rule rule)
    {
        var errors = new Dictionary<string, string>();

        bool addressAction = rule.Action is PolicyAction.BlockInboundIp or PolicyAction.BlockOutboundIp;
        bool portAction = rule.Action is PolicyAction.BlockInboundPort or PolicyAction.BlockOutboundPort;

        if (addressAction && !NetworkAddress.IsValid(rule.SourceIp))
        {
            errors[nameof(Rule.SourceIp)] = "Enter a valid IPv4 address.";
        }

        if (rule.Action == PolicyAction.BlockOutboundIp && !NetworkAddress.IsValid(rule.DestinationIp))
        {
            errors[nameof(Rule.DestinationIp)] = "Enter a valid IPv4 address.";
        }

        ValidatePortAction(rule, portAction, errors);
        ValidatePortRanges(rule, errors);

        return errors;
    }

    private static void ValidatePortAction(Rule rule, bool portAction, Dictionary<string, string> errors)
    {
        if (portAction && rule.Protocol == ProtocolNumbers.Icmp)
        {
            errors[nameof(Rule.Action)] = "Port actions are not valid for ICMP; use an IP action instead.";
        }

        if (portAction && rule.Protocol == 0)
        {
            errors[nameof(Rule.Protocol)] = "Port actions require a specific protocol (TCP or UDP), not Any.";
        }
    }

    private static void ValidatePortRanges(Rule rule, Dictionary<string, string> errors)
    {
        if (rule.SourcePort is { } sourcePort && (sourcePort < 0 || sourcePort > 65535))
        {
            errors[nameof(Rule.SourcePort)] = "Port must be between 0 and 65535.";
        }

        if (rule.DestinationPort is { } destinationPort && (destinationPort < 0 || destinationPort > 65535))
        {
            errors[nameof(Rule.DestinationPort)] = "Port must be between 0 and 65535.";
        }
    }

    public Rule Create(Rule rule, string? alertId, string? policyId, int? durationValue, string? durationUnit)
    {
        var source = string.IsNullOrEmpty(alertId)
            ? null
            : _unitOfWork.Alerts.GetByIdAsync(alertId).GetAwaiter().GetResult();
        var alert = source ?? BuildManualAlert(rule);

        string? resolvedAlertId = source?.Id;
        string? resolvedPolicyId = string.IsNullOrEmpty(policyId)
            ? null
            : _unitOfWork.Policies.GetByIdAsync(policyId).GetAwaiter().GetResult()?.Id;

        var decision = new Decision { Alert = alert, Action = rule.Action };

        var created = _firewall.Apply(decision, resolvedPolicyId, resolvedAlertId, alert.AttackType, ResolveDuration(durationValue, durationUnit));
        _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();
        return created;
    }

    public Rule? Update(Rule rule, int? durationValue, string? durationUnit)
    {
        var updated = _firewall.Update(
            rule.Id,
            rule.SourceIp ?? string.Empty,
            rule.SourcePort ?? 0,
            rule.DestinationIp ?? string.Empty,
            rule.DestinationPort ?? 0,
            rule.Protocol ?? 0,
            rule.Action,
            rule.Status,
            ResolveDuration(durationValue, durationUnit));

        if (updated is not null)
        {
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();
        }

        return updated;
    }

    public bool Remove(string ruleId)
    {
        bool removed = _firewall.Remove(ruleId);
        if (removed)
        {
            _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();
        }
        return removed;
    }

    public int RemoveAll()
    {
        int removed = _firewall.RemoveAll();
        _unitOfWork.SaveChangesAsync().GetAwaiter().GetResult();
        return removed;
    }

    public static TimeSpan ResolveDuration(int? value, string? unit)
    {
        if (!value.HasValue || value.Value <= 0)
        {
            return TimeSpan.FromMinutes(60);
        }

        return unit switch
        {
            "hours" => TimeSpan.FromHours(value.Value),
            "days" => TimeSpan.FromDays(value.Value),
            _ => TimeSpan.FromMinutes(value.Value)
        };
    }

    private static Alert BuildManualAlert(Rule rule) => new()
    {
        DetectionSource = DetectionSource.None,
        AttackType = AttackTypes.Benign,
        SourceIp = rule.SourceIp ?? string.Empty,
        SourcePort = rule.SourcePort ?? 0,
        DestinationIp = rule.DestinationIp ?? string.Empty,
        DestinationPort = rule.DestinationPort ?? 0,
        Protocol = rule.Protocol ?? 0
    };
}
