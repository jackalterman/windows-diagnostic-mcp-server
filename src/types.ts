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
  DeviceID?: string;
  SerialNumber?: string;
  FirmwareVersion?: string;
  Manufacturer?: string;
  MediaType?: string;
  BusType?: number;
  Attributes: {
    Size: number;
    Interface: string;
    Partitions?: number;
    SectorsPerTrack?: number;
    TracksPerCylinder?: number;
    TotalCylinders?: number;
    TotalHeads?: number;
    TotalSectors?: number;
    BytesPerSector?: number;
    Capabilities?: number[];
    CapabilityDescriptions?: string[];
    CompressionMethod?: string;
    ConfigManagerErrorCode?: number;
    ConfigManagerUserConfig?: boolean;
    DefaultBlockSize?: number;
    Index?: number;
    InstallDate?: string;
    LastErrorCode?: number;
    MaxBlockSize?: number;
    MinBlockSize?: number;
    NeedsCleaning?: boolean;
    NumberOfMediaSupported?: number;
    PNPDeviceID?: string;
    PowerManagementCapabilities?: number[];
    PowerManagementSupported?: boolean;
    SCSIBus?: number;
    SCSILogicalUnit?: number;
    SCSIPort?: number;
    SCSITargetId?: number;
    SCSITerminated?: boolean;
    Signature?: number;
    Status?: string;
    StatusInfo?: number;
    SystemName?: string;
    TimeOfLastReset?: string;
  };
  SMARTAttributes?: {
    VendorSpecific?: number[];
    VendorSpecificLength?: number;
  };
  TemperatureThresholds?: {
    VendorSpecific?: number[];
    VendorSpecificLength?: number;
  };
}

export interface RAMModule {
  CapacityGB: number;
  Speed?: number;
  Manufacturer?: string;
  PartNumber?: string;
  SerialNumber?: string;
  FormFactor?: number;
  MemoryType?: number;
  DeviceLocator?: string;
  BankLabel?: string;
  ConfiguredClockSpeed?: number;
  ConfiguredVoltage?: number;
}

export interface MemoryHealth {
  Status: string;
  Errors: string[];
  TotalMemoryGB?: number;
  UsedMemoryGB?: number;
  FreeMemoryGB?: number;
  UsagePercent?: number;
  RAMModules?: RAMModule[];
}

export interface DiskUsage {
  Drive: string;
  Label?: string;
  FileSystem?: string;
  TotalSizeGB: number;
  UsedSizeGB: number;
  FreeSizeGB: number;
  UsagePercent: number;
  Status: string;
}

export interface LargeFile {
  Path: string;
  SizeMB: number;
  SizeGB: number;
  LastModified: string;
  Extension?: string;
}

export interface LargeFolder {
  Path: string;
  SizeMB: number;
  SizeGB: number;
  LastModified: string;
  ItemCount: number;
}

export interface HardwareMonitorOutput {
  Temperatures: TemperatureReading[];
  FanSpeeds: FanSpeedReading[];
  SMARTStatus: SmartStatus[];
  MemoryHealth: MemoryHealth;
  DiskUsage: DiskUsage[];
  LargeFiles: LargeFile[];
  LargeFolders: LargeFolder[];
  Errors: string[];
}

export interface HardwareMonitorParams {
  checkTemperatures?: boolean;
  checkFanSpeeds?: boolean;
  checkSmartStatus?: boolean;
  checkMemoryHealth?: boolean;
  checkDiskUsage?: boolean;
  scanLargeFiles?: boolean;
  debug?: boolean;
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

// Event Viewer Types (to be added to types.js)
export interface EventViewerParams {
  // Search parameters
  SearchKeyword?: string;
  EventIDs?: number[];
  Sources?: string[];
  LogNames?: string[];
  Hours?: number;
  Days?: number;
  StartTime?: string;
  EndTime?: string;
  MaxEventsPerLog?: number;
  IncludeDisabledLogs?: boolean;
  ErrorsOnly?: boolean;
  WarningsOnly?: boolean;
  CriticalOnly?: boolean;
  InformationOnly?: boolean;
  SkipSecurityLog?: boolean;
  IncludeSystemLogs?: boolean;
  IncludeApplicationLogs?: boolean;
  DeepSearch?: boolean;
  Detailed?: boolean;
  SearchTerms?: string[];
  SecurityAnalysis?: boolean;
  ExportJson?: boolean;
  ExportCsv?: boolean;
  OutputPath?: string;
}

export interface EventViewerEvent {
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

export interface SecurityAnalysis {
  LogonEvents: {
    Successful: number;
    Failed: number;
    Logoffs: number;
    ExplicitCredentialUse: number;
  };
  FailedLogons: Array<{
    Account: string;
    Attempts: number;
  }>;
  AccountLockouts: EventViewerEvent[];
  PrivilegeUse: EventViewerEvent[];
  PolicyChanges: EventViewerEvent[];
  SuspiciousActivity: string[];
}

export interface ErrorPatterns {
  TotalErrors: number;
  TotalWarnings: number;
  TopErrorEventIds: Array<{
    ID: number;
    Count: number;
  }>;
  TopErrorSources: Array<{
    Source: string;
    Count: number;
  }>;
  RecentErrorCount: number;
}

export interface UnifiedEventViewerOutput {
  // Core metadata
  Timestamp: string;
  ComputerName: string;
  
  // Analysis period
  AnalysisPeriod: {
    StartTime: string;
    EndTime: string;
    Duration: string;
  };
  
  // Search criteria
  SearchCriteria: {
    Keyword: string;
    EventIDs: number[];
    Sources: string[];
    TimeRange: { StartTime: string; EndTime: string; Duration: string; };
    MaxEventsPerLog: number;
  };
  
  // Log discovery
  LogDiscovery: LogDiscoveryInfo;
  
  // Log summary
  LogSummary: Record<string, any>;
  
  // Search results
  SearchResults: SearchResults;
  
  // Analysis features
  SecurityAnalysis: SecurityAnalysis;
  ErrorPatterns: ErrorPatterns;
  Statistics: Record<string, any>;
  Recommendations: string[];
  
  // Events
  Events: EventViewerEvent[];
  
  // Performance
  Performance: {
    SearchDuration: number;
    LogsProcessed: number;
    AverageTimePerLog: number;
  };
  
  // Errors and warnings
  Errors: string[];
  Warnings: string[];
  
  // Debug information (when Debug: true)
  DebugInfo?: {
    ParameterValues: Record<string, any>;
    ExecutionSteps: string[];
  };
}

// Add these interfaces to src/types.ts

export interface AdminDetails {
  CurrentUser: string;
  AuthenticationType: string;
  IsSystem: boolean;
  IsGuest: boolean;
  IsAnonymous: boolean;
}

export interface DomainInfo {
  ComputerName: string;
  Domain?: string;
  DomainRole?: number;
  Workgroup?: string;
  IsPartOfDomain?: boolean;
  IsDomainController?: boolean;
  DomainName?: string;
  Forest?: string;
  DomainControllers?: string[];
  Error?: string;
}

export interface PowerShellInfo {
  CurrentUserPolicy: string;
  LocalMachinePolicy: string;
  ProcessPolicy: string;
  EffectivePolicy: string;
  PSVersion: string;
  PSEdition: string;
  CanRunScripts: boolean;
  PolicyFixed?: boolean;
  NewPolicy?: string;
}

export interface SystemInfo {
  OS: string;
  Version: string;
  Build: string;
  TotalRAM_GB: number;
  Architecture: string;
  LogicalProcessors: string;
  PowerShellHost: string;
  PowerShellVersion: string;
}

export interface UsageGuideSection {
  [key: string]: string | string[];
}

export interface UsageGuide {
  QuickStart: UsageGuideSection;
  CommonWorkflows: {
    TroubleshootCrashes: string[];
    PerformanceAnalysis: string[];
    SecurityAudit: string[];
  };
  ToolCategories: {
    SystemHealth: string[];
    Hardware: string[];
    Events: string[];
    Registry: string[];
    Processes: string[];
    Startup: string[];
  };
  PermissionNotes: {
    RequiredForMost: string;
    CanRunWithoutAdmin: string[];
    AdminRecommended: string[];
  };
}

export interface SystemInfoSummary {
  Administrator: boolean;
  DomainJoined: boolean;
  ScriptsEnabled: boolean;
  ReadyForDiagnostics: boolean;
}

export interface SystemInfoOutput {
  IsAdministrator: boolean;
  AdminDetails: AdminDetails;
  DomainInfo: DomainInfo;
  PowerShellInfo: PowerShellInfo;
  SystemInfo?: SystemInfo;
  UsageGuide: UsageGuide;
  Recommendations: string[];
  Errors: string[];
  Warnings: string[];
  Summary: SystemInfoSummary;
}

export interface SystemInfoParams {
  FixExecutionPolicy?: boolean;
  ShowHelp?: boolean;
  Detailed?: boolean;
}

// Driver Scanner Types
export interface DriverInfo {
  DriverName: string;
  Description: string;
  DeviceClass: string;
  Manufacturer: string;
  DriverVersion: string;
  DriverDate: string;
  DriverPathName: string;
  IsSigned: boolean;
  IsEnabled: boolean;
  Signer: string;
  DeviceID: string;
  HardwareID: string;
  CompatID: string;
  InfName: string;
  InfSection: string;
  InfSectionExt: string;
  ProviderName: string;
  DriverDateLocal: string;
  DriverVersionLocal: string;
  SecurityIssues?: string[];
  HealthIssues?: string[];
  VersionIssues?: string[];
  // Detailed fields (when Detailed: true)
  DriverType?: number;
  DriverRank?: number;
  DriverProvider?: string;
  DriverMfgName?: string;
  DriverOEMInf?: string;
  DriverOEMInfExt?: string;
  DriverInfName?: string;
  DriverInfSection?: string;
  DriverInfSectionExt?: string;
  DriverInfFileName?: string;
  DriverInfDir?: string;
  DriverInfDate?: string;
  DriverInfVersion?: string;
  DriverInfSize?: number;
  DriverInfSizeLocal?: number;
  DriverInfDateLocal?: string;
  DriverInfVersionLocal?: string;
}

export interface DriverSummary {
  TotalDrivers: number;
  SignedDrivers: number;
  UnsignedDrivers: number;
  EnabledDrivers: number;
  DisabledDrivers: number;
  DriversWithErrors: number;
  OutdatedDrivers: number;
  SecurityIssues: number;
}

export interface SecurityAnalysis {
  UnsignedDrivers: DriverInfo[];
  SuspiciousDrivers: DriverInfo[];
  VulnerableDrivers: DriverInfo[];
  CertificateIssues: DriverInfo[];
}

export interface HealthAnalysis {
  ErrorDevices: DriverInfo[];
  MissingDrivers: DriverInfo[];
  OutdatedDrivers: DriverInfo[];
  PerformanceIssues: DriverInfo[];
}

export interface DriverScannerOutput {
  Drivers: DriverInfo[];
  Summary: DriverSummary;
  SecurityAnalysis: SecurityAnalysis;
  HealthAnalysis: HealthAnalysis;
  Errors: string[];
}

export interface DriverScannerParams {
  driverName?: string;
  deviceClass?: string;
  manufacturer?: string;
  signedOnly?: boolean;
  unsignedOnly?: boolean;
  enabledOnly?: boolean;
  disabledOnly?: boolean;
  withErrors?: boolean;
  checkSecurity?: boolean;
  checkVersions?: boolean;
  checkHealth?: boolean;
  detailed?: boolean;
}