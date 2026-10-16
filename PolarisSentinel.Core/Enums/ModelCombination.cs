namespace PolarisSentinel.Core.Enums;

public enum ModelCombination
{
    RandomForestOnly,

    IsolationForestOnly,

    IsolationThenRandomForest,

    RandomForestThenIsolation,

    ParallelRandomForestAndIsolation
}
