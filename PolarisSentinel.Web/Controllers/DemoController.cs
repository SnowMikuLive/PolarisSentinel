using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;

namespace PolarisSentinel.Web.Controllers
{
    [Authorize]
    public class DemoController : Controller
    {
        private readonly IDetectionPipeline _pipeline;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IInferenceEngine _inference;
        private readonly ILogger<DemoController> _logger;

        public DemoController(
            IDetectionPipeline pipeline,
            IUnitOfWork unitOfWork,
            IInferenceEngine inference,
            ILogger<DemoController> logger)
        {
            _pipeline = pipeline;
            _unitOfWork = unitOfWork;
            _inference = inference;
            _logger = logger;
        }

        [Route("simulate")]
        public IActionResult Index()
        {
            return View("~/Views/Demo/Index.cshtml");
        }

        [HttpPost]
        [Route("api/demo/inject")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Inject(
            [FromBody] InjectAttackRequest request,
            CancellationToken cancellationToken)
        {
            var policies = await _unitOfWork.Policies.GetAllAsync(cancellationToken);
            if (policies.Count == 0)
            {
                return BadRequest(new { error = "No policy configured." });
            }

            var flow = BuildFlow(request);
            var policy = SelectPolicy(policies, request);
            if (policy == null)
            {
                return BadRequest(new { error = "No policy matches the requested attack." });
            }

            var detection = _pipeline.ProcessFlow(flow, policy);

            _logger.LogInformation(
                "Demo injection: {AttackType} from {SourceIp} -> {Action} ({Reason}), rule {RuleName}",
                detection.AttackType, detection.SourceIp, detection.Action, detection.Reason, detection.RuleName);

            return Ok(new
            {
                alertId = detection.Id,
                attackType = detection.AttackType,
                source = detection.Source.ToString(),
                sourceIp = detection.SourceIp,
                destinationIp = detection.DestinationIp,
                destinationPort = detection.DestinationPort,
                protocol = detection.Protocol,
                confidence = detection.Confidence,
                action = detection.Action.ToString(),
                reason = detection.Reason,
                ruleName = detection.RuleName,
                policyId = policy.Id,
                decidedAt = detection.DecidedAt.ToString("yyyy-MM-dd HH:mm:ss")
            });
        }

        [HttpGet]
        [Route("api/demo/policies")]
        public async Task<IActionResult> Policies(CancellationToken cancellationToken)
        {
            var policies = await _unitOfWork.Policies.GetAllAsync(cancellationToken);
            return Ok(policies.Select(p => new
            {
                id = p.Id,
                detectionSource = p.DetectionSource.ToString(),
                matchAttackTypes = p.MatchAttackTypes,
                matchProtocol = p.MatchProtocol,
                blockDurationMinutes = p.BlockDurationMinutes
            }));
        }

        private static FlowFeatureVector BuildFlow(InjectAttackRequest request)
        {
            string attackType = NormalizeAttackType(request.AttackType);
            bool isPreFilter = request.UsePreFilter ?? true;

            return new FlowFeatureVector
            {
                Features = new float[20],
                SourceIp = request.SourceIp ?? "203.0.113.77",
                SourcePort = (ushort)(request.SourcePort ?? 44444),
                DestinationIp = request.DestinationIp ?? "192.168.1.10",
                DestinationPort = (ushort)(request.DestinationPort ?? 80),
                Protocol = request.Protocol ?? ProtocolNumbers.Tcp,
                FlowStartTime = DateTime.Now.AddSeconds(-5),
                FlowEndTime = DateTime.Now,
                TotalPackets = 2000,
                TotalBytes = 2400000,
                PreFilterVerdict = isPreFilter
                    ? new PreFilterResult
                    {
                        AttackType = attackType,
                        Confidence = 1f,
                        Reason = $"demo_{attackType.ToLowerInvariant()}"
                    }
                    : null
            };
        }

        private static string NormalizeAttackType(string? attackType)
        {
            if (AttackTypes.TryParse(attackType, out string parsed) && parsed != AttackTypes.Benign)
            {
                return parsed;
            }

            return AttackTypes.DoS;
        }

        private static Policy? SelectPolicy(IReadOnlyList<Policy> policies, InjectAttackRequest request)
        {
            bool isPreFilter = request.UsePreFilter ?? true;
            string attackType = NormalizeAttackType(request.AttackType);
            byte protocol = request.Protocol ?? ProtocolNumbers.Tcp;

            Policy? best = null;
            int bestScore = -1;

            foreach (var policy in policies)
            {
                bool sourceMatches = isPreFilter
                    ? policy.DetectionSource == DetectionSource.PreFilter
                    : policy.DetectionSource != DetectionSource.PreFilter;
                if (!sourceMatches)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(policy.MatchAttackTypes) &&
                    !policy.MatchAttackTypes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Any(e => string.Equals(e, attackType, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                if (policy.MatchProtocol != 0 && policy.MatchProtocol != protocol)
                {
                    continue;
                }

                int score = 0;
                if (!string.IsNullOrWhiteSpace(policy.MatchAttackTypes))
                {
                    score += 2;
                }
                if (policy.MatchProtocol != 0)
                {
                    score += 1;
                }

                if (score > bestScore)
                {
                    bestScore = score;
                    best = policy;
                }
            }

            return best;
        }
    }

    public class InjectAttackRequest
    {
        public string? AttackType { get; set; }

        public string? SourceIp { get; set; }

        public int? SourcePort { get; set; }

        public string? DestinationIp { get; set; }

        public int? DestinationPort { get; set; }

        public byte? Protocol { get; set; }

        public bool? UsePreFilter { get; set; }
    }
}
