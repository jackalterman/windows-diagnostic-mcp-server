#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive Network Diagnostics Script for Windows Systems
.DESCRIPTION
    Analyzes network connections, WiFi signal strength, DNS resolution, bandwidth, and security
.NOTES
    Requires Administrator privileges for full functionality
    Some features may require specific network adapters or Windows versions
#>

param(
    [switch]$Detailed,
    [switch]$ExportJson,
    [string]$OutputPath = ".\network-report.json",
    [string[]]$TestHosts = @("8.8.8.8", "1.1.1.1", "google.com", "microsoft.com"),
    [int]$BandwidthTestSize = 10, # MB
    [string[]]$PortScanTargets = @("localhost")
)

# Initialize results object
$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    NetworkAdapters = @()
    ActiveConnections = @()
    WiFiNetworks = @()
    DNSResults = @()
    BandwidthTest = @{}
    PortScan = @{}
    FirewallStatus = @{}
    Errors = @()
}

Write-Host "🌐 Network Diagnostics Report - $($Results.Timestamp)" -ForegroundColor Cyan
Write-Host "=" * 60

#region Network Adapter Information
Write-Host "`n🔌 Network Adapters" -ForegroundColor Yellow

try {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($adapter in $adapters) {
        $adapterInfo = @{
            Name = $adapter.Name
            InterfaceDescription = $adapter.InterfaceDescription
            LinkSpeed = $adapter.LinkSpeed
            MacAddress = $adapter.MacAddress
            Status = $adapter.Status
            Type = $adapter.MediaType
            IPv4Address = $null
            IPv6Address = $null
            DefaultGateway = $null
            DNSServers = @()
            SignalStrength = $null
            SSID = $null
        }

        # Get IP configuration
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
        if ($ipConfig) {
            $adapterInfo.IPv4Address = ($ipConfig.IPv4Address | Where-Object { $_.AddressFamily -eq "IPv4" }).IPAddress
            $adapterInfo.IPv6Address = ($ipConfig.IPv6Address | Where-Object { $_.AddressFamily -eq "IPv6" -and $_.Type -eq "Unicast" }).IPAddress
            $adapterInfo.DefaultGateway = $ipConfig.IPv4DefaultGateway.NextHop
            $adapterInfo.DNSServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4).ServerAddresses
        }

        # WiFi specific information
        if ($adapter.MediaType -like "*802.11*" -or $adapter.InterfaceDescription -like "*WiFi*" -or $adapter.InterfaceDescription -like "*Wireless*") {
            try {
                $wifiProfile = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
                $currentProfile = netsh wlan show interfaces | Select-String "Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
                
                if ($currentProfile) {
                    $adapterInfo.SSID = $currentProfile
                    
                    # Get signal strength
                    $signalInfo = netsh wlan show interfaces | Select-String "Signal"
                    if ($signalInfo) {
                        $signalMatch = $signalInfo -match "(\d+)%"
                        if ($signalMatch) {
                            $adapterInfo.SignalStrength = $matches[1] + "%"
                        }
                    }
                }
            } catch {
                $Results.Errors += "WiFi information error for $($adapter.Name): $($_.Exception.Message)"
            }
        }

        $Results.NetworkAdapters += $adapterInfo

        # Display adapter info
        $statusIcon = if ($adapterInfo.Status -eq "Up") { "🟢" } else { "🔴" }
        Write-Host "  $statusIcon $($adapterInfo.Name) ($($adapterInfo.Type))"
        Write-Host "    IP: $($adapterInfo.IPv4Address) | Gateway: $($adapterInfo.DefaultGateway)"
        Write-Host "    Speed: $($adapterInfo.LinkSpeed) | MAC: $($adapterInfo.MacAddress)"
        
        if ($adapterInfo.SSID) {
            Write-Host "    WiFi: $($adapterInfo.SSID) | Signal: $($adapterInfo.SignalStrength)" -ForegroundColor Cyan
        }
    }
} catch {
    Write-Host "  ❌ Error reading network adapters: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Network adapter error: $($_.Exception.Message)"
}
#endregion

#region Active Network Connections
Write-Host "`n🔗 Active Network Connections" -ForegroundColor Yellow

try {
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | 
                   Sort-Object LocalPort | Select-Object -First 20

    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        
        $connectionInfo = @{
            LocalAddress = $conn.LocalAddress
            LocalPort = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort = $conn.RemotePort
            State = $conn.State
            ProcessName = if ($process) { $process.ProcessName } else { "Unknown" }
            ProcessId = $conn.OwningProcess
        }

        $Results.ActiveConnections += $connectionInfo
    }

    # Display top connections
    Write-Host "  📊 Top Active Connections (showing first 10):"
    $Results.ActiveConnections | Select-Object -First 10 | ForEach-Object {
        Write-Host "    🔗 $($_.ProcessName) ($($_.ProcessId)): $($_.LocalAddress):$($_.LocalPort) → $($_.RemoteAddress):$($_.RemotePort)"
    }

    # Connection summary
    $totalConnections = (Get-NetTCPConnection).Count
    $establishedConnections = (Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }).Count
    $listeningPorts = (Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }).Count

    Write-Host "`n  📈 Connection Summary:"
    Write-Host "    Total connections: $totalConnections"
    Write-Host "    Established: $establishedConnections"
    Write-Host "    Listening ports: $listeningPorts"

} catch {
    Write-Host "  ❌ Error reading network connections: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Network connections error: $($_.Exception.Message)"
}
#endregion

#region WiFi Network Scanning
Write-Host "`n📶 Available WiFi Networks" -ForegroundColor Yellow

try {
    # Get available WiFi networks
    $wifiOutput = netsh wlan show profiles
    $wifiNetworks = netsh wlan show profiles | Select-String "All User Profile" | 
                   ForEach-Object { ($_ -split ":")[-1].Trim() }

    if ($wifiNetworks) {
        foreach ($network in $wifiNetworks | Select-Object -First 10) {
            try {
                $profileDetails = netsh wlan show profile name="$network" key=clear
                $authentication = ($profileDetails | Select-String "Authentication" | Select-Object -First 1) -replace ".*:\s*", ""
                $encryption = ($profileDetails | Select-String "Cipher" | Select-Object -First 1) -replace ".*:\s*", ""
                
                $wifiInfo = @{
                    SSID = $network
                    Authentication = $authentication.Trim()
                    Encryption = $encryption.Trim()
                    Saved = $true
                }
                
                $Results.WiFiNetworks += $wifiInfo
                Write-Host "  📶 $network - Auth: $($wifiInfo.Authentication) | Enc: $($wifiInfo.Encryption)"
            } catch {
                Write-Host "  ⚠️  Could not get details for network: $network" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  ⚠️  No saved WiFi networks found" -ForegroundColor Yellow
    }

    # Try to get available networks (scan)
    try {
        $availableNetworks = netsh wlan show networks mode=bssid
        Write-Host "`n  🔍 Scanning for available networks..."
        # Note: Parsing netsh output for available networks would require more complex string parsing
        # This is a simplified version
    } catch {
        Write-Host "  ⚠️  Could not scan for available networks" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  ❌ Error scanning WiFi networks: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "WiFi scanning error: $($_.Exception.Message)"
}
#endregion

#region DNS Resolution Testing
Write-Host "`n🔍 DNS Resolution Testing" -ForegroundColor Yellow

foreach ($host in $TestHosts) {
    try {
        $dnsStart = Get-Date
        $dnsResult = Resolve-DnsName -Name $host -ErrorAction Stop
        $dnsEnd = Get-Date
        $dnsTime = ($dnsEnd - $dnsStart).TotalMilliseconds

        $dnsInfo = @{
            Hostname = $host
            ResolvedIP = $dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -First 1 -ExpandProperty IPAddress
            ResponseTime = [math]::Round($dnsTime, 2)
            Status = "Success"
            RecordType = $dnsResult[0].Type
        }

        $Results.DNSResults += $dnsInfo
        Write-Host "  🟢 $host → $($dnsInfo.ResolvedIP) ($($dnsInfo.ResponseTime)ms)"

    } catch {
        $dnsInfo = @{
            Hostname = $host
            ResolvedIP = $null
            ResponseTime = $null
            Status = "Failed"
            Error = $_.Exception.Message
        }
        $Results.DNSResults += $dnsInfo
        Write-Host "  🔴 $host → Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test DNS servers response time
Write-Host "`n  🏃 DNS Server Performance:"
$dnsServers = @("8.8.8.8", "1.1.1.1", "208.67.222.222") # Google, Cloudflare, OpenDNS

foreach ($dnsServer in $dnsServers) {
    try {
        $pingResult = Test-Connection -ComputerName $dnsServer -Count 1 -ErrorAction Stop
        Write-Host "    🟢 $dnsServer : $($pingResult.ResponseTime)ms"
    } catch {
        Write-Host "    🔴 $dnsServer : Unreachable" -ForegroundColor Red
    }
}
#endregion

#region Bandwidth Testing
Write-Host "`n⚡ Bandwidth Testing" -ForegroundColor Yellow

try {
    # Simple bandwidth test using ping and file operations
    Write-Host "  📊 Running basic connectivity tests..."
    
    $bandwidthResults = @{
        PingTests = @()
        LocalPerformance = @{}
    }

    # Ping test to various servers
    $pingTargets = @("8.8.8.8", "1.1.1.1", "google.com")
    foreach ($target in $pingTargets) {
        try {
            $pingStats = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop
            $avgPing = ($pingStats | Measure-Object -Property ResponseTime -Average).Average
            $minPing = ($pingStats | Measure-Object -Property ResponseTime -Minimum).Minimum
            $maxPing = ($pingStats | Measure-Object -Property ResponseTime -Maximum).Maximum
            
            $pingInfo = @{
                Target = $target
                AverageMs = [math]::Round($avgPing, 2)
                MinimumMs = $minPing
                MaximumMs = $maxPing
                PacketLoss = 0
                Status = "Success"
            }
            
            $bandwidthResults.PingTests += $pingInfo
            Write-Host "  🟢 $target : Avg $($pingInfo.AverageMs)ms (Min: $($pingInfo.MinimumMs)ms, Max: $($pingInfo.MaximumMs)ms)"
            
        } catch {
            $pingInfo = @{
                Target = $target
                Status = "Failed"
                Error = $_.Exception.Message
            }
            $bandwidthResults.PingTests += $pingInfo
            Write-Host "  🔴 $target : Failed - $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Local network performance (if available)
    $perfCounters = @(
        "\Network Interface(*)\Bytes Total/sec",
        "\Network Interface(*)\Current Bandwidth"
    )

    foreach ($counter in $perfCounters) {
        try {
            $perfData = Get-Counter -Counter $counter -ErrorAction SilentlyContinue
            # Process performance counter data (simplified)
        } catch {
            # Ignore performance counter errors
        }
    }

    $Results.BandwidthTest = $bandwidthResults

} catch {
    Write-Host "  ❌ Error during bandwidth testing: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Bandwidth testing error: $($_.Exception.Message)"
}
#endregion

#region Port Scanning
Write-Host "`n🚪 Port Scanning" -ForegroundColor Yellow

foreach ($target in $PortScanTargets) {
    Write-Host "  🔍 Scanning $target..."
    
    $commonPorts = @(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3389, 5432, 8080)
    $openPorts = @()
    
    foreach ($port in $commonPorts) {
        try {
            $connection = New-Object System.Net.Sockets.TcpClient
            $connection.ConnectAsync($target, $port).Wait(1000)
            
            if ($connection.Connected) {
                $openPorts += $port
                $connection.Close()
            }
        } catch {
            # Port is closed or filtered
        }
    }
    
    $Results.PortScan[$target] = @{
        OpenPorts = $openPorts
        ScannedPorts = $commonPorts
        Timestamp = Get-Date
    }
    
    if ($openPorts.Count -gt 0) {
        Write-Host "    🟢 Open ports: $($openPorts -join ', ')"
    } else {
        Write-Host "    🔒 No common ports open"
    }
}
#endregion

#region Firewall Status
Write-Host "`n🛡️  Windows Firewall Status" -ForegroundColor Yellow

try {
    $firewallProfiles = Get-NetFirewallProfile
    
    foreach ($profile in $firewallProfiles) {
        $profileInfo = @{
            Name = $profile.Name
            Enabled = $profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction
            DefaultOutboundAction = $profile.DefaultOutboundAction
            AllowInboundRules = $profile.AllowInboundRules
            AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
            NotifyOnListen = $profile.NotifyOnListen
        }
        
        $Results.FirewallStatus[$profile.Name] = $profileInfo
        
        $statusIcon = if ($profile.Enabled) { "🟢" } else { "🔴" }
        Write-Host "  $statusIcon $($profile.Name) Profile: $(if ($profile.Enabled) { 'Enabled' } else { 'Disabled' })"
        Write-Host "    Inbound: $($profile.DefaultInboundAction) | Outbound: $($profile.DefaultOutboundAction)"
    }
    
    # Get firewall rules count
    $inboundRules = (Get-NetFirewallRule -Direction Inbound -Enabled True).Count
    $outboundRules = (Get-NetFirewallRule -Direction Outbound -Enabled True).Count
    
    Write-Host "`n  📋 Firewall Rules Summary:"
    Write-Host "    Active Inbound Rules: $inboundRules"
    Write-Host "    Active Outbound Rules: $outboundRules"
    
    # Check for common security rules
    $remoteDesktopRule = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -Enabled True -ErrorAction SilentlyContinue
    $fileShareRule = Get-NetFirewallRule -DisplayName "*File and Printer Sharing*" -Enabled True -ErrorAction SilentlyContinue
    
    if ($remoteDesktopRule) {
        Write-Host "    ⚠️  Remote Desktop rules are enabled" -ForegroundColor Yellow
    }
    if ($fileShareRule) {
        Write-Host "    ⚠️  File and Printer Sharing rules are enabled" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  ❌ Error reading firewall status: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Firewall status error: $($_.Exception.Message)"
}
#endregion

#region Network Security Analysis
Write-Host "`n🔒 Network Security Analysis" -ForegroundColor Yellow

try {
    # Check for suspicious connections
    $suspiciousConnections = Get-NetTCPConnection | Where-Object { 
        $_.RemoteAddress -notlike "127.*" -and 
        $_.RemoteAddress -notlike "192.168.*" -and 
        $_.RemoteAddress -notlike "10.*" -and 
        $_.RemoteAddress -notlike "172.*" -and
        $_.State -eq "Established"
    } | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 5

    if ($suspiciousConnections) {
        Write-Host "  🔍 Top External Connections:"
        foreach ($conn in $suspiciousConnections) {
            $processes = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq $conn.Name } | 
                        ForEach-Object { 
                            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                            if ($proc) { $proc.ProcessName }
                        } | Select-Object -Unique
            Write-Host "    🌐 $($conn.Name) ($($conn.Count) connections) - Processes: $($processes -join ', ')"
        }
    }

    # Check network shares
    $networkShares = Get-SmbShare | Where-Object { $_.Name -ne "IPC$" -and $_.Name -ne "ADMIN$" -and $_.Name -notlike "*$" }
    if ($networkShares) {
        Write-Host "`n  📁 Active Network Shares:"
        foreach ($share in $networkShares) {
            Write-Host "    📂 $($share.Name): $($share.Path) - $($share.Description)"
        }
    }

    # Check for weak WiFi security
    if ($Results.WiFiNetworks) {
        $weakWiFi = $Results.WiFiNetworks | Where-Object { 
            $_.Authentication -like "*WEP*" -or 
            $_.Authentication -like "*Open*" -or 
            $_.Encryption -like "*WEP*" 
        }
        
        if ($weakWiFi) {
            Write-Host "`n  ⚠️  Weak WiFi Security Detected:" -ForegroundColor Yellow
            foreach ($network in $weakWiFi) {
                Write-Host "    🔓 $($network.SSID): $($network.Authentication)/$($network.Encryption)" -ForegroundColor Yellow
            }
        }
    }

} catch {
    Write-Host "  ❌ Error during security analysis: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Security analysis error: $($_.Exception.Message)"
}
#endregion

#region Internet Connectivity Tests
Write-Host "`n🌍 Internet Connectivity Tests" -ForegroundColor Yellow

try {
    # Test various internet services
    $internetTests = @(
        @{ Name = "Google DNS"; Target = "8.8.8.8"; Port = 53 },
        @{ Name = "Cloudflare DNS"; Target = "1.1.1.1"; Port = 53 },
        @{ Name = "HTTP (Google)"; Target = "google.com"; Port = 80 },
        @{ Name = "HTTPS (Google)"; Target = "google.com"; Port = 443 },
        @{ Name = "NTP"; Target = "pool.ntp.org"; Port = 123 }
    )

    foreach ($test in $internetTests) {
        try {
            if ($test.Port -eq 53) {
                # DNS test
                $dnsTest = Resolve-DnsName -Name "google.com" -Server $test.Target -ErrorAction Stop
                Write-Host "  🟢 $($test.Name): DNS resolution successful"
            } elseif ($test.Port -eq 80 -or $test.Port -eq 443) {
                # HTTP/HTTPS test
                $protocol = if ($test.Port -eq 443) { "https" } else { "http" }
                $response = Invoke-WebRequest -Uri "${protocol}://$($test.Target)" -TimeoutSec 10 -ErrorAction Stop
                Write-Host "  🟢 $($test.Name): HTTP $($response.StatusCode) - $($response.StatusDescription)"
            } else {
                # Generic port test
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $result = $tcpClient.ConnectAsync($test.Target, $test.Port).Wait(5000)
                if ($tcpClient.Connected) {
                    Write-Host "  🟢 $($test.Name): Port $($test.Port) accessible"
                    $tcpClient.Close()
                } else {
                    Write-Host "  🔴 $($test.Name): Port $($test.Port) not accessible" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "  🔴 $($test.Name): Failed - $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Test internet speed (basic)
    Write-Host "`n  ⚡ Basic Speed Test:"
    try {
        $speedTestStart = Get-Date
        $speedTestUrl = "http://speedtest.ftp.otenet.gr/files/test1Mb.db"  # 1MB test file
        $tempFile = [System.IO.Path]::GetTempFileName()
        
        Invoke-WebRequest -Uri $speedTestUrl -OutFile $tempFile -TimeoutSec 30 -ErrorAction Stop
        $speedTestEnd = Get-Date
        $downloadTime = ($speedTestEnd - $speedTestStart).TotalSeconds
        $fileSize = (Get-Item $tempFile).Length / 1MB
        $speedMbps = [math]::Round(($fileSize * 8) / $downloadTime, 2)
        
        Write-Host "    📊 Download Speed: ~$speedMbps Mbps (1MB test file in $([math]::Round($downloadTime, 2))s)"
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        
        $Results.BandwidthTest.DownloadSpeedMbps = $speedMbps
        $Results.BandwidthTest.TestFileSize = "1MB"
        
    } catch {
        Write-Host "    ⚠️  Speed test failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

} catch {
    Write-Host "  ❌ Error during internet connectivity tests: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Internet connectivity test error: $($_.Exception.Message)"
}
#endregion

#region Route Table Analysis
Write-Host "`n🗺️  Network Route Analysis" -ForegroundColor Yellow

try {
    # Get routing table
    $routes = Get-NetRoute | Where-Object { $_.RouteMetric -lt 1000 } | 
              Sort-Object RouteMetric | Select-Object -First 10
    
    Write-Host "  📍 Top Network Routes:"
    foreach ($route in $routes) {
        $routeInfo = "    🛤️  $($route.DestinationPrefix) → $($route.NextHop)"
        if ($route.InterfaceAlias) {
            $routeInfo += " (via $($route.InterfaceAlias))"
        }
        $routeInfo += " [Metric: $($route.RouteMetric)]"
        Write-Host $routeInfo
    }

    # Trace route to important destinations
    Write-Host "`n  🎯 Trace Route Analysis:"
    $traceTargets = @("8.8.8.8", "google.com")
    
    foreach ($target in $traceTargets) {
        try {
            Write-Host "    📡 Tracing route to $target..."
            $traceResult = Test-NetConnection -ComputerName $target -TraceRoute -ErrorAction Stop
            $hopCount = $traceResult.TraceRoute.Count
            Write-Host "      Hops: $hopCount | Final destination: $($traceResult.RemoteAddress)"
            
            if ($Detailed -and $traceResult.TraceRoute) {
                $traceResult.TraceRoute | ForEach-Object -Begin { $hop = 1 } -Process {
                    Write-Host "        $hop. $_"
                    $hop++
                }
            }
        } catch {
            Write-Host "      ❌ Trace route failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

} catch {
    Write-Host "  ❌ Error analyzing network routes: $($_.Exception.Message)" -ForegroundColor Red
    $Results.Errors += "Route analysis error: $($_.Exception.Message)"
}
#endregion

#region Summary and Recommendations
Write-Host "`n📋 Network Health Summary" -ForegroundColor Green

# Calculate health scores
$adapterHealth = if ($Results.NetworkAdapters.Count -gt 0) { "Good" } else { "Poor" }
$dnsHealth = if (($Results.DNSResults | Where-Object { $_.Status -eq "Success" }).Count -ge 2) { "Good" } else { "Poor" }
$connectivityHealth = if ($Results.ActiveConnections.Count -gt 0) { "Good" } else { "Poor" }
$firewallHealth = if (($Results.FirewallStatus.Values | Where-Object { $_.Enabled }).Count -ge 2) { "Good" } else { "Poor" }

Write-Host "  🎯 Overall Network Health:"
Write-Host "    Network Adapters: $adapterHealth ($($Results.NetworkAdapters.Count) active)"
Write-Host "    DNS Resolution: $dnsHealth ($($Results.DNSResults | Where-Object { $_.Status -eq 'Success' } | Measure-Object).Count/$($Results.DNSResults.Count) successful)"
Write-Host "    Connectivity: $connectivityHealth ($($Results.ActiveConnections.Count) active connections)"
Write-Host "    Firewall: $firewallHealth"

if ($Results.BandwidthTest.DownloadSpeedMbps) {
    Write-Host "    Internet Speed: $($Results.BandwidthTest.DownloadSpeedMbps) Mbps"
}

# Recommendations
Write-Host "`n💡 Recommendations:" -ForegroundColor Cyan
$recommendations = @()

if ($Results.Errors.Count -gt 3) {
    $recommendations += "Multiple errors detected - consider running as Administrator"
}

if ($Results.FirewallStatus.Values | Where-Object { -not $_.Enabled }) {
    $recommendations += "Enable Windows Firewall on all network profiles"
}

if ($Results.WiFiNetworks | Where-Object { $_.Authentication -like "*WEP*" -or $_.Authentication -like "*Open*" }) {
    $recommendations += "Upgrade weak WiFi security (avoid WEP/Open networks)"
}

if ($Results.BandwidthTest.DownloadSpeedMbps -and $Results.BandwidthTest.DownloadSpeedMbps -lt 10) {
    $recommendations += "Internet speed appears slow - check with ISP"
}

if ($Results.ActiveConnections.Count -gt 100) {
    $recommendations += "High number of network connections - monitor for suspicious activity"
}

if ($recommendations.Count -gt 0) {
    foreach ($rec in $recommendations) {
        Write-Host "    • $rec" -ForegroundColor Yellow
    }
} else {
    Write-Host "    ✅ No immediate issues detected" -ForegroundColor Green
}

if ($Results.Errors.Count -gt 0) {
    Write-Host "`n⚠️  Errors encountered: $($Results.Errors.Count)" -ForegroundColor Yellow
    if ($Detailed) {
        foreach ($error in $Results.Errors) {
            Write-Host "    • $error" -ForegroundColor Yellow
        }
    }
}
#endregion

#region Export Results
# Export to JSON if requested
if ($ExportJson) {
    try {
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "`n📄 Report exported to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "`n❌ Failed to export report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n✅ Network diagnostics complete!" -ForegroundColor Green
Write-Host "📊 Statistics:"
Write-Host "  • Network Adapters: $($Results.NetworkAdapters.Count)"
Write-Host "  • Active Connections: $($Results.ActiveConnections.Count)"
Write-Host "  • WiFi Networks: $($Results.WiFiNetworks.Count)"
Write-Host "  • DNS Tests: $($Results.DNSResults.Count)"
Write-Host "  • Errors: $($Results.Errors.Count)"
#endregion