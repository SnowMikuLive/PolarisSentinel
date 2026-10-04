using System.Net;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using Decision = PolarisSentinel.Core.Models.PolicyDecision;

namespace PolarisSentinel.Application;

// Application use case for manual firewall-rule management: validates operator input,
// builds the alert a manual rule is based on, and drives the firewall enforcer.
// Controllers stay thin and delegate here instead of embedding domain rules.
public class RuleManagementService
{
    private readonly IFirewallEnforcer _firewall;
    private readonly IUnitOfWork _unitOfWork;

    public RuleManagementService(IFirewallEnforcer firewall, IUnitOfWork unitOfWork)
    {
        _firewall = firewall;
        _unitOfWork = unitOfWork;
    }

    // Validates a rule's 5-tuple and action. Returns the validation errors keyed by field.
    public IReadOnlyDictionary<string, string> Validate(Rule rule)
    {
        var errors = new Dictionary<string, string>();

        if (string.IsNullOrWhiteSpace(rule.SourceIp) && string.IsNullOrWhiteSpace(rule.DestinationIp))
        {
            errors[nameof(Rule.SourceIp)] = "Provide at least one address, or pick Any on both sides.";
        }

        if (!IsValidAddress(rule.SourceIp))
        {
            errors[nameof(Rule.SourceIp)] = "Enter a valid IP address or CIDR.";
        }

        if (!IsValidAddress(rule.DestinationIp))
        {
            errors[nameof(Rule.DestinationIp)] = "Enter a valid IP address or CIDR.";
        }

        // ICMP has no ports, so a port-based action cannot be expressed.
        bool portAction = rule.Action is PolicyAction.BlockInboundPort or PolicyAction.BlockOutboundPort;
        if (portAction && rule.Protocol == ProtocolNumbers.Icmp)
        {
            errors[nameof(Rule.Action)] = "Port actions are not valid for ICMP; use an IP action instead.";
        }

        return errors;
    }

    // Creates a rule from operator input. When alertId is supplied the rule keeps that
    // alert's real 5-tuple and origin; otherwise a synthetic alert is built from the input.
    public Rule Create(Rule rule, string? alertId, string? policyId, int? durationValue, string? durationUnit)
    {
        var alert = string.IsNullOrEmpty(alertId)
            ? BuildManualAlert(rule)
            : _unitOfWork.Alerts.GetByIdAsync(alertId).GetAwaiter().GetResult() ?? BuildManualAlert(rule);

        var decision = new Decision { Alert = alert, Action = rule.Action };

        var created = _firewall.Apply(decision, policyId, alertId, alert.AttackType, ResolveDuration(durationValue, durationUnit));
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

    // Convert value + unit into a duration; default 60 minutes.
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

    // A synthetic alert carrying the operator's 5-tuple; it is never persisted.
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

    private static bool IsValidAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return IPAddress.TryParse(value.Split('/')[0], out _);
    }
}
