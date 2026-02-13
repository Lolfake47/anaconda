export enum ScanType {
  TCP = 'TCP',
  UDP = 'UDP',
  DIR = 'DIR'
}

export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface StealthSettings {
  timing: 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5';
  fragmentation: boolean;
  decoys: boolean;
  sourcePortSpoofing: boolean;
  macSpoofing: boolean;
  dynamicMacRotation: boolean;
  traceObfuscation: boolean;
  identityScrambling: boolean;
  payloadRandomization: boolean; // New: Randomized injection patterns
}

export interface TargetProfile {
  id: string;
  name: string;
  target: string;
  commonPorts: string;
  description: string;
  createdAt: string;
}

export interface DiscoveredDirectory {
  path: string;
  status: number;
  size: string;
  type: string;
  vulnerability?: string; // Potential injection type found
  payload?: string; // Example payload that triggered response
  mitigation?: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  type: ScanType;
  openPorts: number[];
  services: Record<number, string>;
  vulnerabilities: Vulnerability[];
  directories: DiscoveredDirectory[];
  stealthUsed: StealthSettings;
}

export interface Vulnerability {
  id: string;
  name: string;
  cve?: string;
  severity: Severity;
  description: string;
  exploitTheory: string;
  exploitationSteps: string[];
  exploitUrl: string;
  mitigation: string;
}

export interface AIAnalysisResponse {
  summary: string;
  riskScore: number;
  recommendations: string[];
  exploitPaths: string[];
  traceRisk: number;
}

export interface HttpRequest {
  method: string;
  url: string;
  headers: string;
  body: string;
}