// Tipos espelhando a serialização dos crates Rust e chamadas aos comandos
// Tauri. Nenhuma lógica de negócio aqui: regras ficam no backend (mex-app).

import { invoke } from "@tauri-apps/api/core";

export type Id = string;
export type Timestamp = string; // UTC canônico: YYYY-MM-DDTHH:MM:SS.ffffffZ

export interface Digest {
  alg: "sha-256";
  hex: string;
}

export interface AppError {
  kind: string;
  message: string;
}

export function isAppError(e: unknown): e is AppError {
  return typeof e === "object" && e !== null && "message" in e && "kind" in e;
}

export function errorMessage(e: unknown): string {
  if (isAppError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

export interface Operator {
  id: Id;
  full_name: string;
  badge: string;
  organization: string;
  created_at: Timestamp;
}

export interface Case {
  id: Id;
  number: string;
  title: string;
  created_by: Id;
  created_at: Timestamp;
}

export interface CaseSummary {
  case: Case;
  status: string;
  authorizations: number;
  acquisitions: number;
}

export type AuthorizationKind = "judicial-warrant" | "owner-consent" | "other";

export interface Authorization {
  id: Id;
  case_id: Id;
  kind: AuthorizationKind;
  kind_detail: string | null;
  reference: string;
  issuer: string;
  scope_notes: string | null;
  document_sha256: Digest | null;
  recorded_by: Id;
  recorded_at: Timestamp;
}

export type Platform = "android" | "ios" | "simulated";
export type AdbState = "device" | "unauthorized" | "offline" | { other: string };

export interface DeviceObservation {
  platform: Platform;
  serial: string;
  manufacturer: string | null;
  model: string | null;
  os_version: string | null;
  security_patch: string | null;
  adb_state: AdbState | null;
  observed_at: Timestamp;
}

export interface Device {
  id: Id;
  observed: DeviceObservation;
  first_seen: Timestamp;
}

export type ModificationRisk = "none" | "low" | "high";

export type Availability =
  | { status: "available" }
  | { status: "unavailable"; reason: string }
  | { status: "not-implemented" };

export interface Capability {
  kind: string;
  availability: Availability;
  prerequisites: string[];
  limitations: string[];
  modification_risk: ModificationRisk;
}

export interface AdapterDescriptor {
  id: string;
  version: string;
  platforms: Platform[];
  capabilities: string[];
  prerequisites: string[];
  restrictions: string[];
  modification_risk: ModificationRisk;
}

export interface ImportPreview {
  case: Case;
  authorization: Authorization;
  device: Device;
  adapter: AdapterDescriptor;
  capability: Capability;
  source_dir: string;
  evidence_root: string;
}

export type RunStatus =
  | { kind: "running" }
  | { kind: "finished"; outcome: string; reason: string | null }
  | { kind: "error"; message: string };

export interface RunView {
  acquisition_id: Id;
  case_id: Id;
  source_dir: string;
  started_at: Timestamp;
  finished_at: Timestamp | null;
  cancel_requested: boolean;
  status: RunStatus;
}

export interface AcquisitionView {
  id: Id;
  case_id: Id;
  device_id: Id;
  authorization_id: Id;
  operator_id: Id;
  capability: string;
  adapter_id: string;
  adapter_version: string;
  software_version: string;
  outcome: string | null;
  limitations: string[];
  started_at: Timestamp;
  finished_at: Timestamp | null;
  package_path: string | null;
  manifest_sha256: string | null;
  job_state: string | null;
  bytes_acquired: number;
  artifacts_completed: number;
  artifacts_failed: number;
  last_verification: string | null;
}

export interface ArtifactView {
  stored_path: string;
  source_path: string | null;
  source_modified: Timestamp | null;
  size_bytes: number;
  status: string;
  failure_reason: string | null;
  sha256: string | null;
}

export interface Finding {
  subject: string;
  kind: string;
  [field: string]: unknown;
}

export interface VerificationReport {
  package_dir: string;
  status: "intact" | "compromised" | "incomplete";
  acquisition_id: Id | null;
  manifest_sha256: Digest | null;
  artifacts_checked: number;
  bytes_verified: number;
  findings: Finding[];
  verified_at: Timestamp;
}

export interface VerificationView {
  status: string;
  manifest_sha256: string | null;
  artifacts_checked: number;
  bytes_verified: number;
  findings: Finding[];
  verified_by: Id;
  verified_at: Timestamp;
}

export interface ReportView {
  acquisition_id: Id | null;
  format: string;
  stored_path: string;
  sha256: string;
  generated_by: Id;
  generated_at: Timestamp;
}

export interface ExportView {
  destination: string;
  status: string;
  files_copied: number;
  bytes_copied: number;
  exported_by: Id;
  exported_at: Timestamp;
}

export interface ReportOutput {
  integrity: string;
  html_path: string;
  html_sha256: string;
  json_path: string;
  json_sha256: string;
}

export interface ExportOutput {
  status: string;
  destination: string | null;
  files_copied: number;
  bytes_copied: number;
}

export interface AuditEvent {
  seq: number;
  id: Id;
  case_id: Id | null;
  operator_id: Id | null;
  kind: string;
  detail: string;
  at: Timestamp;
  prev_hash: string | null;
  entry_hash: string;
}

export interface CustodyView {
  events: AuditEvent[];
  chain_intact: boolean;
  chain_problem: string | null;
  chain_length: number;
  chain_head_hash: string | null;
}

export interface Stats {
  cases: number;
  devices: number;
  acquisitions: number;
  acquisitions_open: number;
  artifacts_complete: number;
  audit_events: number;
}

export interface AppInfo {
  data_dir: string;
  database: string;
  evidence_root: string;
  reports_root: string;
  versions: [string, string][];
  session: Operator | null;
  recovered_on_open: number;
}

export interface MethodPolicy {
  status: string;
  allowed_in_case: boolean;
  reason: string | null;
}

export interface NewOperator {
  full_name: string;
  badge: string;
  organization: string;
}

export interface NewAuthorization {
  case_id: Id;
  kind: AuthorizationKind;
  kind_detail: string | null;
  reference: string;
  issuer: string;
  scope_notes: string | null;
  document_path: string | null;
}

export interface NewDevice {
  case_id: Id | null;
  platform: Exclude<Platform, "simulated">;
  serial: string;
  manufacturer: string | null;
  model: string | null;
  os_version: string | null;
  security_patch: string | null;
}

export interface ImportRequest {
  case_id: Id;
  authorization_id: Id;
  device_id: Id;
  source_dir: string;
  operator_confirmed: boolean;
}

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  stats: () => invoke<Stats>("stats"),
  listOperators: () => invoke<Operator[]>("list_operators"),
  registerOperator: (input: NewOperator) => invoke<Operator>("register_operator", { input }),
  selectOperator: (id: Id) => invoke<Operator>("select_operator", { id }),
  endSession: () => invoke<void>("end_session"),
  listCases: () => invoke<CaseSummary[]>("list_cases"),
  getCase: (id: Id) => invoke<Case>("get_case", { id }),
  createCase: (number: string, title: string) => invoke<Case>("create_case", { input: { number, title } }),
  listAuthorizations: (caseId: Id) => invoke<Authorization[]>("list_authorizations", { caseId }),
  recordAuthorization: (input: NewAuthorization) => invoke<Authorization>("record_authorization", { input }),
  listDevices: () => invoke<Device[]>("list_devices"),
  getDevice: (id: Id) => invoke<Device>("get_device", { id }),
  registerDevice: (input: NewDevice) => invoke<Device>("register_device", { input }),
  previewImport: (caseId: Id, authorizationId: Id, deviceId: Id, sourceDir: string) =>
    invoke<ImportPreview>("preview_import", { caseId, authorizationId, deviceId, sourceDir }),
  startImport: (input: ImportRequest) => invoke<RunView>("start_import", { input }),
  listRuns: () => invoke<RunView[]>("list_runs"),
  cancelRun: (acquisitionId: Id) => invoke<void>("cancel_run", { acquisitionId }),
  listAcquisitions: (caseId: Id | null, deviceId: Id | null) =>
    invoke<AcquisitionView[]>("list_acquisitions", { caseId, deviceId }),
  listArtifacts: (acquisitionId: Id) => invoke<ArtifactView[]>("list_artifacts", { acquisitionId }),
  verify: (acquisitionId: Id) => invoke<VerificationReport>("verify", { acquisitionId }),
  listVerifications: (acquisitionId: Id) => invoke<VerificationView[]>("list_verifications", { acquisitionId }),
  generateReport: (acquisitionId: Id) => invoke<ReportOutput>("generate_report", { acquisitionId }),
  listReports: (caseId: Id) => invoke<ReportView[]>("list_reports", { caseId }),
  exportPackage: (acquisitionId: Id, destDir: string) =>
    invoke<ExportOutput>("export_package", { acquisitionId, destDir }),
  listExports: (acquisitionId: Id) => invoke<ExportView[]>("list_exports", { acquisitionId }),
  custody: (caseId: Id) => invoke<CustodyView>("custody", { caseId }),
  researchPolicy: () => invoke<MethodPolicy[]>("research_policy"),
};
