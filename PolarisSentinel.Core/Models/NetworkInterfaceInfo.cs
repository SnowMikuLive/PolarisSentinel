namespace PolarisSentinel.Core.Models
{
    public class NetworkInterfaceInfo
    {
        public required string DeviceName { get; set; }
        public required string DisplayName { get; set; }
        public string? IpAddress { get; set; }
    }
}
