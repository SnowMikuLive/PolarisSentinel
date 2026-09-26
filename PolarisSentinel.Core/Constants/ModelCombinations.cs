namespace PolarisSentinel.Core.Constants;

using PolarisSentinel.Core.Enums;

// Display names and helpers for the five AI engine configurations.
public static class ModelCombinations
{
    public static readonly ModelCombination[] All = Enum.GetValues<ModelCombination>();

    // Human-readable label shown on the Dashboard, Inference Results and Charts pages.
    public static string DisplayName(ModelCombination combination) => combination switch
    {
        ModelCombination.RandomForestOnly => "Random Forest Only",
        ModelCombination.IsolationForestOnly => "Isolation Forest Only",
        ModelCombination.IsolationThenRandomForest => "Isolation Forest -> Random Forest",
        ModelCombination.RandomForestThenIsolation => "Random Forest -> Isolation Forest",
        ModelCombination.ParallelRandomForestAndIsolation => "Parallel Random Forest + Isolation Forest",
        _ => combination.ToString()
    };
}
