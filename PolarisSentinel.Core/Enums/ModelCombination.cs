namespace PolarisSentinel.Core.Enums;

// The five AI engine configurations selectable by the user.
public enum ModelCombination
{
    RandomForestOnly,

    IsolationForestOnly,

    IsolationThenRandomForest,

    RandomForestThenIsolation,

    ParallelRandomForestAndIsolation
}
