import { z } from 'zod';

// Type definitions for the PowerShell script results
export interface EventInfo {
  Type: string;
  Time: string;
  EventID: number;
  Source: string;
  Description: string;
  Details: string;
}

export interface ApplicationCrash {
  Application: string;
  CrashCount: number;
  LatestCrash: string;
}

export interface UpdateEvent {
  Time: string;
  EventID: number;
  Source: string;
  Description: string;
}

export interface DriverIssue {
  DriverService: string;
  IssueCount: number;
}

export interface HardwareError {
  Time: string;
  Source: string;
  Details: string;
}

export interface SystemInfo {
  CurrentUptimeDays: number;
  CurrentUptimeHours: number;
  CurrentUptimeMinutes: number;
  LastBootTime: string;
  RebootCountInPeriod: number;
  OSVersion: string;
  TotalMemoryGB: number;
}

export interface MemoryDump {
  Type: string;
  Path: string;
  LastWrite: string;
  SizeMB?: number;
  SizeKB?: number;
}

export interface Summary {
  TotalEventsAnalyzed: number;
  CriticalBSODCount: number;
  UnexpectedShutdownCount: number;
  TotalApplicationCrashes: number;
  AnalysisPeriodDays: number;
  GeneratedAt: string;
}

export interface DiagnosticResults {
  ShutdownEvents: EventInfo[];
  BSODEvents: EventInfo[];
  ApplicationCrashes: ApplicationCrash[];
  UpdateEvents: UpdateEvent[];
  DriverIssues: DriverIssue[];
  HardwareErrors: HardwareError[];
  SystemInfo: SystemInfo;
  MemoryDumps: MemoryDump[];
  Summary: Summary;
}

// Type definitions for the registry script results
export interface RegistrySearchResult {
  Type: string;        // matches PowerShell "Type"
  Path: string;        // matches PowerShell "Path" 
  ValueName: string;   // matches
  ValueData: string;   // matches
  Match: string;       // matches PowerShell "Match"
  Found: string;       // matches PowerShell "Found"
}

export interface StartupProgram {
  Name: string;
  Command: string;
  Location: string;
  User: string;
  Verified: boolean;
  Suspicious: boolean;
}

export interface SystemComponent {
  Type: string;
  Name: string;
  Issue: string;
  Details: string;
}

export interface OrphanedEntry {
  Path: string;
  Type: string;
}

export interface RegistryHealth {
  Score: number;
  Rating: string;
  IssuesFound: number;
  Recommendations: string[];
}

export interface SecurityFinding {
  ID: string;
  Severity: string;
  Description: string;
  Details: string;
  Recommendation: string;
}

export interface RegistryDiagnosticResults {
  SearchResults?: RegistrySearchResult[];
  StartupPrograms?: StartupProgram[];
  SystemComponents?: SystemComponent[];
  OrphanedEntries?: OrphanedEntry[];
  RegistryHealth?: RegistryHealth;
  SecurityFindings?: SecurityFinding[];
  Summary: {
    ScanType: string;
    ItemsScanned: number;
    IssuesFound: number;
    GeneratedAt: string;
  };
}

// Type definitions for the apps and processes script results
export interface RunningProcess {
  Name: string;
  PID: number;
  CPU: number;
  MemoryMB: number;
  User: string;
}

export interface KilledProcess {
  PID?: number;
  Name?: string;
  Error?: string;
}

export interface StartedProcess {
  Name?: string;
  PID?: number;
  Path: string;
  Error?: string;
}

export interface InstalledApplication {
  Name: string;
  Version: string;
  Publisher: string;
  InstallDate: string;
}

export interface AppsAndProcessesResults {
  RunningProcesses?: RunningProcess[];
  KilledProcesses?: KilledProcess[];
  StartedProcess?: StartedProcess;
  InstalledApplications?: InstalledApplication[];
}

// Type definitions for the hardware monitor script results
export const hardwareMonitorParamsSchema = z.object({
  checkTemperatures: z.boolean().default(true),
  checkFanSpeeds: z.boolean().default(true),
  checkSmartStatus: z.boolean().default(true),
  checkMemoryHealth: z.boolean().default(true),
});

export type HardwareMonitorParams = z.infer<typeof hardwareMonitorParamsSchema>;

export interface TemperatureReading {
  Sensor: string;
  TemperatureC: number;
}

export interface FanSpeedReading {
  Fan: string;
  SpeedRPM: number;
}

export interface SmartStatus {
  Disk: string;
  Status: string;
  Attributes: Record<string, unknown>;
}

export interface MemoryHealth {
  Status: string;
  Errors: any[];
}

export interface HardwareMonitorOutput {
  Temperatures: TemperatureReading[];
  FanSpeeds: FanSpeedReading[];
  SMARTStatus: SmartStatus[];
  MemoryHealth: MemoryHealth;
  Errors: string[];
}

export interface Tool {
    name: string;
    description: string;
    schema: z.ZodObject<any>;
    execute: (params: any) => Promise<any>;
  }

// Type definitions for the network diagnostic script results
export const networkDiagnosticParamsSchema = z.object({
    detailed: z.boolean().optional().default(false),
    testHosts: z.array(z.string()).optional().default(["8.8.8.8", "1.1.1.1", "google.com"]),
    bandwidthTestSize: z.number().int().positive().optional().default(10),
    portScanTargets: z.array(z.string()).optional().default(["localhost"]),
});

export type NetworkDiagnosticParams = z.infer<typeof networkDiagnosticParamsSchema>;

export interface NetworkAdapterInfo {
    Name: string;
    InterfaceDescription: string;
    LinkSpeed: number;
    MacAddress: string;
    Status: string;
    Type: string;
    IPv4Address: string | null;
    IPv6Address: string | null;
    DefaultGateway: string | null;
    DNSServers: string[];
    SignalStrength: string | null;
    SSID: string | null;
}

export interface ActiveConnection {
    LocalAddress: string;
    LocalPort: number;
    RemoteAddress: string;
    RemotePort: number;
    State: string;
    ProcessName: string;
    ProcessId: number;
}

export interface WiFiNetwork {
    SSID: string;
    Authentication: string;
    Encryption: string;
    Saved: boolean;
}

export interface DnsResult {
    Hostname: string;
    ResolvedIP: string | null;
    ResponseTime: number | null;
    Status: "Success" | "Failed";
    RecordType?: string;
    Error?: string;
}

export interface PingTest {
    Target: string;
    AverageMs: number | null;
    MinimumMs: number | null;
    MaximumMs: number | null;
    PacketLoss?: number;
    Status: "Success" | "Failed";
    Error?: string;
}

export interface BandwidthTest {
    PingTests: PingTest[];
    DownloadSpeedMbps?: number;
    TestFileSize?: string;
}

export interface PortScanResult {
    OpenPorts: number[];
    ScannedPorts: number[];
    Timestamp: string;
}

export interface FirewallProfile {
    Name: string;
    Enabled: boolean;
    DefaultInboundAction: string;
    DefaultOutboundAction: string;
}

export interface NetworkDiagnosticOutput {
    Timestamp: string;
    ComputerName: string;
    NetworkAdapters: NetworkAdapterInfo[];
    ActiveConnections: ActiveConnection[];
    WiFiNetworks: WiFiNetwork[];
    DNSResults: DnsResult[];
    BandwidthTest: BandwidthTest;
    PortScan: Record<string, PortScanResult>;
    FirewallStatus: Record<string, FirewallProfile>;
    Errors: string[];
}

// Type definitions for the comprehensive event viewer search tool
export interface EventViewerSearchEvent {
  TimeCreated: string;
  LogName: string;
  Level: number;
  LevelDisplayName: string;
  Id: number;
  ProviderName: string;
  TaskDisplayName: string;
  Message: string;
  UserId: string;
  ProcessId: number;
  ThreadId: number;
  MachineName: string;
  RecordId: number;
}

export interface LogDiscoveryInfo {
  TotalLogsFound: number;
  EnabledLogs: number;
  DisabledLogs: number;
  AccessibleLogs: number;
  InaccessibleLogs: number;
  LogsSearched: Array<{
    LogName: string;
    EventsFound: number;
    SearchTime: number;
  }>;
  LogsSkipped: Array<{
    LogName: string;
    Reason: string;
    Error?: string;
  }>;
  AllLogs?: Array<{
    LogName: string;
    IsEnabled: boolean;
    RecordCount: number;
    FileSize: number;
    LastWriteTime: string;
  }>;
}

export interface SearchResults {
  TotalEventsFound: number;
  EventsByLog: Record<string, number>;
  EventsByLevel: Record<string, number>;
  EventsBySource: Record<string, number>;
  TopEventIDs: Array<{
    EventID: number;
    Count: number;
  }>;
}

export interface EventViewerSearchOutput {
  Timestamp: string;
  ComputerName: string;
  SearchCriteria: {
    Keyword: string;
    EventIDs: number[];
    Sources: string[];
    TimeRange: {
      StartTime: string;
      EndTime: string;
      Duration: string;
    };
    MaxEventsPerLog: number;
  };
  LogDiscovery: LogDiscoveryInfo;
  SearchResults: SearchResults;
  Events: EventViewerSearchEvent[];
  Errors: string[];
  Warnings: string[];
  Performance: {
    SearchDuration: number;
    LogsProcessed: number;
    AverageTimePerLog: number;
  };
}
