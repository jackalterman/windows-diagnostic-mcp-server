
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
  Hive: string;
  KeyPath: string;
  ValueName: string;
  ValueData: string;
  MatchType: string;
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
