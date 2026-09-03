namespace PolarisSentinel.TrafficCapture.Internal;

internal sealed class RunningStats
{
    private int _count;
    private double _mean;
    private double _m2;
    private double _min = double.MaxValue;   
    private double _max = double.MinValue;  


    public double Min => _count > 0 ? _min : 0;
    public double Max => _count > 0 ? _max : 0;

    public void Add(double value)
    {
        _count++;
        double delta = value - _mean;
        _mean += delta / _count;
        _m2 += delta * (value - _mean);

        if (value < _min) _min = value;
        if (value > _max) _max = value;
    }
    //Welford's algorithm for calculate data stram mean and standard devation
    public int Count => _count;
    public double Mean => _count > 0 ? _mean : 0;
    public double StdDev => _count > 1 ? Math.Sqrt(_m2 / (_count - 1)) : 0;
}