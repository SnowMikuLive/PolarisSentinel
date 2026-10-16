namespace PolarisSentinel.Web.Service;

public static class SearchFilter
{
    public static bool Contains(string? value, string term) =>
        !string.IsNullOrEmpty(value) && value.Contains(term, StringComparison.OrdinalIgnoreCase);
}
