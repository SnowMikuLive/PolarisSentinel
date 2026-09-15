using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Inference;

namespace PolarisSentienlUnitTestProject
{
    [TestClass]
    public class LegacyFeatureAdapterTests
    {
        #region Conversion Tests

        // 20/24 维抓包特征都能映射到 ML 契约
        // Both 20-D and 24-D capture vectors map to the ML contract
        [TestMethod]
        [DataRow(20)]
        [DataRow(24)]
        public void LegacyFeatureAdapter_ToContract_ShouldConvertCaptureFeatures(int length)
        {
            // Arrange
            float[] legacy = { 2, 4, 2, 800, 200, 1, 100, 40, 5, 11, 12, 13, 14, 15, 16, 17, 18, 99, 99, 99 };
            Array.Resize(ref legacy, length);
            float[] expected = { 2000, 4, 2, 800, 200, 1, 100, 40, 5, 11, 12, 13, 14, 15, 16, 17, 18, 0.5f, 0.003f, 0.5f };

            // Act
            var result = LegacyFeatureAdapter.ToContract(legacy);

            // Assert
            CollectionAssert.AreEqual(expected, result);
            Assert.AreEqual(2f, legacy[0]);
            Assert.AreEqual(99f, legacy[17]);
        }

        [TestMethod]
        public void LegacyFeatureAdapter_ToContract_ZeroDurationAndForwardPackets_ShouldReturnZeroRates()
        {
            // Arrange
            var legacy = new float[20];
            legacy[2] = 2;
            legacy[4] = 200;

            // Act
            var result = LegacyFeatureAdapter.ToContract(legacy);

            // Assert
            Assert.AreEqual(0f, result[17]);
            Assert.AreEqual(0f, result[18]);
            Assert.AreEqual(0f, result[19]);
        }

        [TestMethod]
        public void LegacyFeatureAdapter_ToContract_WrongLength_ShouldThrow()
        {
            // Arrange
            var legacy = new float[21];

            // Act and Assert
            Assert.Throws<ArgumentException>(() => LegacyFeatureAdapter.ToContract(legacy));
        }

        #endregion
    }
}
