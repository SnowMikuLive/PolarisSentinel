using System;
using System.Collections.Generic;
using System.Text;

namespace PolarisSentinel.Core.Models
{
    public class NetworkInterfaceInfo
    {
        public required string DeviceName { get; set; }
        public required string DisplayName { get; set; }
        public string? IpAddress { get; set; }
    }
}
