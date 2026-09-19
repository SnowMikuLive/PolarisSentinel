namespace PolarisSentinel.Inference
{
    // 将抓包特征对齐 ML 20 维契约
    // Align capture features with the ML 20-D contract
    public static class LegacyFeatureAdapter
    {
        public static float[] ToContract(float[] legacy)
        {
            if (legacy.Length != 20 && legacy.Length != 24)
                throw new ArgumentException("Capture features must contain 20 or 24 values.", nameof(legacy));

            // 前17项相同
            // The first 17 values are the same
            var features = new float[20];
            Array.Copy(legacy, features, 17);

            // 抓包时长是秒，模型需要毫秒
            // Convert capture seconds to model milliseconds
            features[0] = legacy[0] * 1000;
            features[17] = features[0] > 0 ? (features[3] + features[4]) / features[0] : 0;
            features[18] = features[0] > 0 ? (features[1] + features[2]) / features[0] : 0;
            features[19] = features[1] > 0 ? features[2] / features[1] : 0;
            return features;
        }
    }
}