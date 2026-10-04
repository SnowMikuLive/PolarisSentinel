using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Application;

namespace PolarisSentienlUnitTestProject;

// Exercises the five AI engine configurations with stubbed models.
[TestClass]
public class ModelCombinationServiceTests
{
    [TestMethod]
    public void RandomForestOnly_ShouldReturnRfResult()
    {
        var service = CreateService(rfAttack: AttackTypes.DoS, rfConfidence: 0.9f, anomaly: false);

        var result = service.Run(CreateFlow(), ModelCombination.RandomForestOnly);

        Assert.AreEqual(AttackTypes.DoS, result.AttackType);
        Assert.AreEqual(0.9f, result.ConfidenceScore, 0.0001f);
    }

    [TestMethod]
    public void IsolationForestOnly_ShouldReturnAnomaly()
    {
        var service = CreateService(rfAttack: AttackTypes.Benign, rfConfidence: 0f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.IsolationForestOnly);

        Assert.AreEqual(AttackTypes.UnknownAnomaly, result.AttackType);
    }

    [TestMethod]
    public void IsolationForestOnly_ShouldReturnBenignWhenNormal()
    {
        var service = CreateService(rfAttack: AttackTypes.Benign, rfConfidence: 0f, anomaly: false);

        var result = service.Run(CreateFlow(), ModelCombination.IsolationForestOnly);

        Assert.AreEqual(AttackTypes.Benign, result.AttackType);
    }

    [TestMethod]
    public void IsolationThenRandomForest_NormalFlow_ShouldBeBenign()
    {
        var service = CreateService(rfAttack: AttackTypes.DoS, rfConfidence: 0.9f, anomaly: false);

        var result = service.Run(CreateFlow(), ModelCombination.IsolationThenRandomForest);

        Assert.AreEqual(AttackTypes.Benign, result.AttackType);
    }

    [TestMethod]
    public void IsolationThenRandomForest_AnomalyWithKnownAttack_ShouldReturnRfType()
    {
        var service = CreateService(rfAttack: AttackTypes.PortScan, rfConfidence: 0.9f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.IsolationThenRandomForest);

        Assert.AreEqual(AttackTypes.PortScan, result.AttackType);
    }

    [TestMethod]
    public void IsolationThenRandomForest_AnomalyWithoutKnownAttack_ShouldReturnAnomaly()
    {
        var service = CreateService(rfAttack: AttackTypes.Benign, rfConfidence: 0f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.IsolationThenRandomForest);

        Assert.AreEqual(AttackTypes.UnknownAnomaly, result.AttackType);
    }

    [TestMethod]
    public void RandomForestThenIsolation_KnownAttack_ShouldSkipIsolation()
    {
        var service = CreateService(rfAttack: AttackTypes.BruteForce, rfConfidence: 0.9f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.RandomForestThenIsolation);

        Assert.AreEqual(AttackTypes.BruteForce, result.AttackType);
    }

    [TestMethod]
    public void RandomForestThenIsolation_BenignButAnomalous_ShouldReturnAnomaly()
    {
        var service = CreateService(rfAttack: AttackTypes.Benign, rfConfidence: 0f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.RandomForestThenIsolation);

        Assert.AreEqual(AttackTypes.UnknownAnomaly, result.AttackType);
    }

    [TestMethod]
    public void Parallel_KnownAttack_ShouldPreferRandomForest()
    {
        var service = CreateService(rfAttack: AttackTypes.PortScan, rfConfidence: 0.9f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.ParallelRandomForestAndIsolation);

        Assert.AreEqual(AttackTypes.PortScan, result.AttackType);
    }

    [TestMethod]
    public void Parallel_BenignButAnomalous_ShouldReturnAnomaly()
    {
        var service = CreateService(rfAttack: AttackTypes.Benign, rfConfidence: 0f, anomaly: true);

        var result = service.Run(CreateFlow(), ModelCombination.ParallelRandomForestAndIsolation);

        Assert.AreEqual(AttackTypes.UnknownAnomaly, result.AttackType);
    }

    [TestMethod]
    public void SetActiveCombination_ShouldChangeTheDefault()
    {
        var service = CreateService(rfAttack: AttackTypes.DoS, rfConfidence: 0.9f, anomaly: false);

        service.SetActiveCombination(ModelCombination.IsolationForestOnly);

        Assert.AreEqual(ModelCombination.IsolationForestOnly, service.ActiveCombination);
    }

    private static ModelCombinationService CreateService(string rfAttack, float rfConfidence, bool anomaly) =>
        new(new StubRandomForest(rfAttack, rfConfidence), new StubIsolationForest(anomaly));

    private static FlowFeatureVector CreateFlow() => new()
    {
        Features = new float[20],
        SourceIp = "203.0.113.66",
        SourcePort = 12345,
        DestinationIp = "192.168.1.10",
        DestinationPort = 80,
        Protocol = ProtocolNumbers.Tcp,
        FlowStartTime = DateTime.UnixEpoch,
        FlowEndTime = DateTime.UnixEpoch.AddSeconds(1)
    };

    private class StubRandomForest : IRandomForestModel
    {
        private readonly string _attackType;
        private readonly float _confidence;

        public StubRandomForest(string attackType, float confidence)
        {
            _attackType = attackType;
            _confidence = confidence;
        }

        public InferenceResult Classify(FlowFeatureVector flow) =>
            new() { AttackType = _attackType, ConfidenceScore = _confidence };

        public bool ExceedsThreshold(InferenceResult result) =>
            result.AttackType != AttackTypes.Benign && result.ConfidenceScore >= 0.6f;

        public float BenignProbability(FlowFeatureVector flow) => 0.9f;
    }

    private class StubIsolationForest : IIsolationForestModel
    {
        private readonly bool _anomaly;

        public StubIsolationForest(bool anomaly)
        {
            _anomaly = anomaly;
        }

        public bool IsAnomaly(FlowFeatureVector flow) => _anomaly;

        public InferenceResult Score(FlowFeatureVector flow) =>
            new() { AttackType = AttackTypes.UnknownAnomaly, ConfidenceScore = 0.8f };
    }
}
