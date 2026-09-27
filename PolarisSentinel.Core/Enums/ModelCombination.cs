namespace PolarisSentinel.Core.Enums;

// The five AI engine configurations selectable by the user.
public enum ModelCombination
{
    // Random Forest only.
    RandomForestOnly,

    // Isolation Forest only.
    IsolationForestOnly,

    // Isolation Forest gates the Random Forest.
    IsolationThenRandomForest,

    // Random Forest gates the Isolation Forest.
    RandomForestThenIsolation,

    // Both models run independently and the results are OR-ed.
    ParallelRandomForestAndIsolation
}
