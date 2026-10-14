namespace PolarisSentinel.Core.Models
{
    // A capture-capable network interface as presented to the operator.
    public class NetworkInterfaceInfo
    {
        public required string DeviceName { get; set; }
        public required string DisplayName { get; set; }
        public string? IpAddress { get; set; }

        // True for the loopback adapter, which never carries the traffic we monitor.
        public bool IsLoopback { get; set; }

        // Physical (MAC) address. Two adapters can share the same friendly display name
        // (e.g. several "Ethernet" ports), so this disambiguates them in the selector.
        public string? MacAddress { get; set; }

        // A saved selection may be stored by libpcap device name or by the friendly display
        // name, so match either, case-insensitively. This keeps the operator's choice across
        // device-name drift caused by reboots, driver reinstalls or adapter re-enables.
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
