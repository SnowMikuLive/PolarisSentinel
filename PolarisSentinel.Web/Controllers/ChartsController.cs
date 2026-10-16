using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolarisSentinel.Application;
using PolarisSentinel.Application.Evaluation;
using PolarisSentinel.Core.Constants;
using PolarisSentinel.Core.Enums;
using PolarisSentinel.Core.Interfaces;
using PolarisSentinel.Core.Models;
using PolarisSentinel.Web.Service;

namespace PolarisSentinel.Web.Controllers
{
    // Model testing and comparison: run a model combination on a test row and
    // compare all five combinations on the loaded dataset.
    [Authorize]
    public class ChartsController : Controller
    {
        private const int PageSize = 20;

        // Cap the uploaded evaluation CSV so a large body cannot exhaust the process.
        private const long MaxUploadBytes = 10 * 1024 * 1024;

        private readonly EvaluationService _evaluation;
        private readonly TestDatasetService _dataset;
        private readonly IInferenceEngine _inference;
        private readonly IModelCombinationService _combinations;
        private readonly IUnitOfWork _uow;

        public ChartsController(
            EvaluationService evaluation,
            TestDatasetService dataset,
            IInferenceEngine inference,
            IModelCombinationService combinations,
            IUnitOfWork uow)
        {
            _evaluation = evaluation;
            _dataset = dataset;
            _inference = inference;
            _combinations = combinations;
            _uow = uow;
        }

        public IActionResult Index(int page = 1)
        {
            PopulateViewBag(page);

            if (TempData["EvaluationResults"] is string json && !string.IsNullOrEmpty(json))
            {
                var results = System.Text.Json.JsonSerializer.Deserialize<List<ModelEvaluationResult>>(json)
                    ?? new List<ModelEvaluationResult>();
                ViewBag.RowCount = TempData["EvaluationRowCount"];
                ViewBag.FileName = TempData["EvaluationFileName"];
                return View(results);
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequestSizeLimit(MaxUploadBytes)]
        public async Task<IActionResult> Upload(IFormFile? dataset, CancellationToken cancellationToken)
        {
            if (dataset == null || dataset.Length == 0)
            {
                TempData["error"] = "Select a CSV file to load.";
                return RedirectToAction(nameof(Index));
            }

            // The parser needs flow rows, not arbitrary files; keep the surface small.
            if (!string.Equals(Path.GetExtension(dataset.FileName), ".csv", StringComparison.OrdinalIgnoreCase))
            {
                TempData["error"] = "Only .csv files can be loaded.";
                return RedirectToAction(nameof(Index));
            }

            string content;
            using (var reader = new StreamReader(dataset.OpenReadStream()))
            {
                content = await reader.ReadToEndAsync(cancellationToken);
            }

            if (!_dataset.Load(dataset.FileName, content, out string? error))
            {
                TempData["error"] = error;
            }
            else
            {
                TempData["success"] = $"Loaded {_dataset.Count} row(s) from {dataset.FileName}.";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Test([FromBody] ModelTestRequest? request, CancellationToken cancellationToken)
        {
            if (request == null || !ModelState.IsValid ||
                !Enum.TryParse<ModelCombination>(request.ModelCombination, out var combination) ||
                !Enum.IsDefined(combination))
            {
                return BadRequest(new { error = "Unknown model combination." });
            }

            var row = request.RowIndex is int rowIndex ? _dataset.Get(rowIndex) : null;
            if (row == null)
            {
                return BadRequest(new { error = "No test row selected. Load a dataset first." });
            }

            var flow = row.Flow;
            var alert = _inference.Detect(flow, combination);
            var threshold = await ResolveThresholdAsync(alert.DetectionSource, cancellationToken);

            bool malicious = alert.AttackType != AttackTypes.Benign;
            bool wouldAlert = malicious && (threshold is null || alert.ConfidenceScore is { } score && score >= threshold);

            return Ok(new
            {
                combination = ModelCombinations.DisplayName(combination),
                attackType = alert.AttackType,
                confidenceScore = alert.ConfidenceScore,
                detectionSource = alert.DetectionSource.ToString(),
                threshold,
                wouldGenerateAlert = wouldAlert,
                description = alert.Description,
                expectedMalicious = row.IsMalicious
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Evaluate()
        {
            if (_dataset.Count == 0)
            {
                TempData["error"] = "No dataset loaded. Upload a CSV file to evaluate.";
                return RedirectToAction(nameof(Index));
            }

            var rows = _dataset.GetPage(0, _dataset.Count);
            var results = _evaluation.EvaluateAll(rows);

            TempData["EvaluationResults"] = System.Text.Json.JsonSerializer.Serialize(results);
            TempData["EvaluationRowCount"] = rows.Count;
            TempData["EvaluationFileName"] = _dataset.FileName;
            return RedirectToAction(nameof(Index));
        }

        private void PopulateViewBag(int page)
        {
            ViewBag.Combinations = ModelCombinations.All;
            ViewBag.DatasetName = _dataset.FileName;
            ViewBag.DatasetCount = _dataset.Count;
            ViewBag.Page = page;
            ViewBag.PageSize = PageSize;
            ViewBag.Rows = _dataset.GetPage((page - 1) * PageSize, PageSize);
            ViewBag.ActiveModel = ModelCombinations.DisplayName(_combinations.ActiveCombination);
        }

        private async Task<float?> ResolveThresholdAsync(DetectionSource source, CancellationToken cancellationToken)
        {
            var policies = await _uow.Policies.GetEnabledAsync(cancellationToken);
            foreach (var policy in policies)
            {
                if (policy.DetectionSource is { } configured && configured != source)
                {
                    continue;
                }

                return policy.ThresholdFor(source);
            }

            return null;
        }
    }

    public class ModelTestRequest
    {
        public string? ModelCombination { get; set; }

        public int? RowIndex { get; set; }
    }
}
