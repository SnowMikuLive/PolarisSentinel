using Microsoft.VisualStudio.TestTools.UnitTesting;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;

namespace PolarisSentienlUnitTestProject
{
    // Every attack type the system can report must come from the AttackType enum.
    [TestClass]
    public class AttackTypeCatalogUnitTest
    {
        // The constants class must not drift from the enum.
        [TestMethod]
        public void AttackTypes_Constants_ShouldAllBeEnumMembers()
        {
            string[] constants =
            [
                AttackTypes.Benign,
                AttackTypes.DoS,
                AttackTypes.PortScan,
                AttackTypes.BruteForce,
                AttackTypes.UnknownAnomaly
            ];

            foreach (string value in constants)
            {
                Assert.IsTrue(AttackTypes.IsDefined(value), $"'{value}' is not an AttackType enum member.");
            }
        }

        // All / Selectable are projections of the enum.
        [TestMethod]
        public void AttackTypes_All_ShouldMatchEnumNames()
        {
            CollectionAssert.AreEquivalent(Enum.GetNames<AttackType>(), AttackTypes.All);
        }

        [TestMethod]
        public void AttackTypes_Selectable_ShouldExcludeBenign()
        {
            CollectionAssert.DoesNotContain(AttackTypes.Selectable, AttackTypes.Benign);
            Assert.HasCount(AttackTypes.All.Length - 1, AttackTypes.Selectable);
        }

        // The enum has exactly the five documented categories.
        [TestMethod]
        public void AttackType_Enum_ShouldHaveFiveCategories()
        {
            Assert.HasCount(5, AttackTypes.All);
        }

        // TryParse accepts only real categories, case-insensitively.
        [TestMethod]
        public void TryParse_ShouldAcceptEnumMembers()
        {
            Assert.IsTrue(AttackTypes.TryParse("DoS", out string dos));
            Assert.AreEqual(AttackTypes.DoS, dos);

            Assert.IsTrue(AttackTypes.TryParse("portscan", out string scan));
            Assert.AreEqual(AttackTypes.PortScan, scan);

            Assert.IsTrue(AttackTypes.TryParse("Unknown_Anomaly", out string anomaly));
            Assert.AreEqual(AttackTypes.UnknownAnomaly, anomaly);
        }

        // Sub-types and free text must be rejected: they are not categories.
        [TestMethod]
        public void TryParse_ShouldRejectNonCategories()
        {
            Assert.IsFalse(AttackTypes.TryParse("SynFlood", out _));
            Assert.IsFalse(AttackTypes.TryParse("SshBruteForce", out _));
            Assert.IsFalse(AttackTypes.TryParse("Manual", out _));
            Assert.IsFalse(AttackTypes.TryParse("", out _));
            Assert.IsFalse(AttackTypes.TryParse(null, out _));
        }

        // The RF model's class names must all be valid categories.
        [TestMethod]
        public void ModelClassNames_ShouldAllBeCategories()
        {
            // Mirrors ml/scripts/prepare_dataset.py CLASS_NAMES.
            string[] modelClassNames = ["Benign", "BruteForce", "DoS", "PortScan"];

            foreach (string name in modelClassNames)
            {
                Assert.IsTrue(AttackTypes.TryParse(name, out _), $"Model class '{name}' is not a category.");
            }
        }

        // The pre-filter only ever emits categories.
        [TestMethod]
        public void PreFilterVerdicts_ShouldAllBeCategories()
        {
            string[] verdicts =
            [
                AttackTypes.DoS,
                AttackTypes.PortScan,
                AttackTypes.BruteForce
            ];

            foreach (string value in verdicts)
            {
                Assert.IsTrue(AttackTypes.IsDefined(value));
            }
        }
    }
}
