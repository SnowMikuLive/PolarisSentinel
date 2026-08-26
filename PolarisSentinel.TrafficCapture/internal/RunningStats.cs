namespace PolarisSentinel.Capture.Internal;

internal sealed class RunningStats
{
    private int _count;
    private double _mean;
    private double _m2;

    public double Min { get; private set; } = double.MaxValue;
    public double Max { get; private set; } = double.MinValue;

    public void Add(double value)
    {
        _count++;
        double delta = value - _mean;
        _mean += delta / _count;
        _m2 += delta * (value - _mean);

        if (value < Min) Min = value;
        if (value > Max) Max = value;
    }

    public int Count => _count;
    public double Mean => _count > 0 ? _mean : 0;
    public double StdDev => _count > 1 ? Math.Sqrt(_m2 / (_count - 1)) : 0;
}
