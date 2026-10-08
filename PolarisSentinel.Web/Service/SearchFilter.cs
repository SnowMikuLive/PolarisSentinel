namespace PolarisSentinel.Web.Service;

// Shared by the list pages' search boxes: a case-insensitive substring test that tolerates
// null fields.
public static class SearchFilter
{
    public static bool Contains(string? value, string term) =>
        !string.IsNullOrEmpty(value) && value.Contains(term, StringComparison.OrdinalIgnoreCase);
}
