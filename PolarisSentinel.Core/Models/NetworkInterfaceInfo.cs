namespace PolarisSentinel.Core.Models
{

    public class NetworkInterfaceInfo
    {
        public required string DeviceName { get; set; }
        public required string DisplayName { get; set; }
        public string? IpAddress { get; set; }

        public bool IsLoopback { get; set; }

        public bool IsDefaultRoute { get; set; }

        public string? MacAddress { get; set; }

        public bool Matches(string? nameOrDisplay)
        {
            if (string.IsNullOrWhiteSpace(nameOrDisplay))
            {
                return false;
            }

            return string.Equals(DeviceName, nameOrDisplay, StringComparison.OrdinalIgnoreCase)
                || string.Equals(DisplayName, nameOrDisplay, StringComparison.OrdinalIgnoreCase);
        }
    }
}
