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

    [Authorize]
    public class ChartsController : Controller
    {
        private const int PageSize = 20;

        public const long MaxUploadBytes = 10 * 1024 * 1024;

        // Multipart framing (boundaries, part headers, the antiforgery field) is added on top of the
        // file itself, so the transport limit has to sit slightly above the file limit. Otherwise a
        // file of exactly 10 MB is refused before the action can explain why.
        public const long MaxRequestBytes = MaxUploadBytes + 64 * 1024;

        private readonly EvaluationService _evaluation;
        private readonly TestDatasetService _dataset;
        private readonly IInferenceEngine _inference;
        private readonly IModelCombinationService _combinations;

        public ChartsController(
            EvaluationService evaluation,
            TestDatasetService dataset,
            IInferenceEngine inference,
            IModelCombinationService combinations)
        {
            _evaluation = evaluation;
            _dataset = dataset;
            _inference = inference;
            _combinations = combinations;
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
        [RequestSizeLimit(MaxRequestBytes)]
        public async Task<IActionResult> Upload(IFormFile? dataset, CancellationToken cancellationToken)
        {
            if (dataset == null || dataset.Length == 0)
            {
                TempData["error"] = "Select a CSV file to load.";
                return RedirectToAction(nameof(Index));
            }

            if (dataset.Length > MaxUploadBytes)
            {
                TempData["error"] =
                    $"The file is {dataset.Length / 1048576.0:0.0} MB, above the {MaxUploadBytes / 1048576} MB limit. "
                    + "Split the dataset into smaller files, or load a representative sample.";
                return RedirectToAction(nameof(Index));
            }

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

            if (!_dataset.Load(dataset.FileName, content, out string? error, out int skippedRows))
            {
                TempData["error"] = error;
            }
            else
            {
                TempData["success"] = $"Loaded {_dataset.Count} row(s) from {dataset.FileName}."
                    + (skippedRows > 0 ? $" Skipped {skippedRows} row(s) with missing or invalid values." : string.Empty);
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Test([FromBody] ModelTestRequest? request)
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

            return Ok(new
            {
                combination = ModelCombinations.DisplayName(combination),
                attackType = alert.AttackType,
                confidenceScore = alert.ConfidenceScore,
                detectionSource = alert.DetectionSource.ToString(),
                description = alert.Description,
                expectedMalicious = row.IsMalicious,
                rowId = (request.RowIndex ?? 0) + 1,
                featureNames = PolarisSentinel.Core.Models.FlowSnapshot.FeatureNames,
                features = flow.Features
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
    }

    public class ModelTestRequest
    {
        public string? ModelCombination { get; set; }

        public int? RowIndex { get; set; }
    }
}
