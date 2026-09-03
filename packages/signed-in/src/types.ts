export const SIGNED_IN_SCHEMA_VERSION = 2 as const;
export const LEGACY_SIGNED_IN_SCHEMA_VERSION = 1 as const;

export type OperationInterface = 'control' | 'http' | 'native';
export type OperationClass = 'credential-control' | 'destructive' | 'mutation' | 'read';
export type PolicyEffect = 'allow' | 'confirm' | 'deny';
export type NativeDelivery = 'environment' | 'none' | 'proxy' | 'session';

export interface CredentialFieldConfig {
  description?: string;
  env?: string;
  helpUrl?: string;
  id: string;
  input?: 'file' | 'secret' | 'text';
  label: string;
  portable?: boolean;
  prefixes?: string[];
  required?: boolean;
  secret?: boolean;
}

export interface SessionResolverConfig {
  args: string[];
  fieldMap?: Record<string, string>;
  format: 'aws-process-json' | 'json' | 'json-file-key' | 'text';
  persist?: boolean;
  targetField?: string;
}

export interface SessionConfig {
  captureLimitBytes?: number;
  env?: Record<string, string>;
  loginArgs: string[];
  remoteLoginArgs?: string[];
  resolvers?: SessionResolverConfig[];
  retain?: boolean;
  verifyArgs?: string[];
}

export interface ExistingLoginPathConfig {
  platform?: 'darwin' | 'linux' | 'win32';
  source: string;
  target: string;
}

export interface ExistingLoginConfig {
  detectArgs: string[];
  identityArgs?: string[];
  identityPattern?: string;
  identityStream?: 'stderr' | 'stdout';
  paths?: ExistingLoginPathConfig[];
  source: string;
}

export interface NativeCliConfig {
  clearEnv?: string[];
  command: string;
  delivery?: NativeDelivery;
  prefixArgs?: string[];
  proxySocket?: {
    configPath: string;
    configTemplate: string;
  };
  trustedExecutable?: string;
  trustedExecutableSha256?: string;
  verifyArgs?: string[];
}

export interface BearerAuthConfig {
  field: string;
  type: 'bearer';
}

export interface HeaderAuthConfig {
  field: string;
  header: string;
  prefix?: string;
  type: 'header';
}

export interface BasicAuthConfig {
  password?: 'empty';
  passwordField?: string;
  type: 'basic';
  usernameField: string;
}

export interface AwsSigV4AuthConfig {
  accessKeyField: string;
  defaultRegion?: string;
  defaultService?: string;
  secretKeyField: string;
  sessionTokenField?: string;
  type: 'aws-sigv4';
}

export interface AppleConnectJwtAuthConfig {
  issuerField: string;
  keyIdField: string;
  privateKeyField: string;
  type: 'apple-connect-jwt';
}

export interface NoAuthConfig {
  type: 'none';
}

export type HttpAuthConfig =
  | AppleConnectJwtAuthConfig
  | AwsSigV4AuthConfig
  | BasicAuthConfig
  | BearerAuthConfig
  | HeaderAuthConfig
  | NoAuthConfig;

export interface HttpGatewayConfig {
  allowHosts?: string[];
  auth: HttpAuthConfig;
  baseUrl: string;
  defaultHeaders?: Record<string, string>;
  egressHosts?: string[];
  healthPath?: string;
}

export interface ProviderPolicyConfig {
  confirmCliPatterns?: string[][];
  denyCliPatterns?: string[][];
  destructiveCliPatterns?: string[][];
  mutatingCliPatterns?: string[][];
}

export interface ProviderConfig {
  category?: 'operator' | 'runtime';
  cli?: NativeCliConfig;
  credentialMode?: 'independent' | 'shared';
  credentials?: CredentialFieldConfig[];
  description?: string;
  docsUrl?: string;
  existingLogin?: ExistingLoginConfig;
  http?: HttpGatewayConfig;
  label: string;
  policy?: ProviderPolicyConfig;
  required?: boolean;
  session?: SessionConfig;
}

export type ServicePingConfig =
  | { interface: 'http'; method?: 'GET' | 'HEAD'; path: string }
  | { args: string[]; interface: 'native' };

export interface ServiceConfig extends ProviderConfig {
  identityArgs?: string[];
  installHint?: string;
  ping?: ServicePingConfig;
  signIn: 'interactive' | 'manual';
  target?: ServiceTargetConfig;
}

export interface ServiceTargetConfig {
  env: string;
  label: string;
  pattern?: string;
}

export interface PolicyRule {
  commandPattern?: string[];
  effect: PolicyEffect;
  environments?: string[];
  id: string;
  interfaces?: OperationInterface[];
  methods?: string[];
  operationClasses?: OperationClass[];
  pathPattern?: string;
  providers?: string[];
  reason: string;
}

export interface SignedInProjectConfig {
  environment?: string;
  policies?: PolicyRule[];
  project: {
    id: string;
    name: string;
  };
  providers: Record<string, ServiceConfig>;
  schemaVersion: typeof SIGNED_IN_SCHEMA_VERSION;
  services: Record<string, ProjectServiceBinding>;
}

export interface LegacySignedInProjectConfig {
  environment?: string;
  policies?: PolicyRule[];
  project: {
    id: string;
    name: string;
  };
  providers: Record<string, ProviderConfig>;
  schemaVersion: typeof LEGACY_SIGNED_IN_SCHEMA_VERSION;
}

export type ProjectServiceBinding = true | string | {
  account?: string;
  alias?: string;
  checks?: ProjectVerificationCheck[];
  expectedIdentity?: string;
  required?: boolean;
  target?: string;
};

export interface ProjectVerificationCheck {
  id: string;
  label?: string;
  method?: 'GET' | 'HEAD';
  path: string;
}

export interface ServiceCatalog {
  schemaVersion: 1;
  services: Record<string, ServiceConfig>;
}

export interface TrustedProject {
  connections?: Record<string, string>;
  config: SignedInProjectConfig;
  fingerprint: string;
  pendingConnections?: string[];
  trustedAt: string;
}

export interface RegisteredProject {
  configPath: string;
  fingerprint: string;
  id: string;
  name: string;
  roots: string[];
  trustedAt: string;
}

export interface MachineIdentityPublic {
  encryptionPublicKey: string;
  fingerprint: string;
  id: string;
  label: string;
  signingPublicKey: string;
}

export interface MachineIdentityPrivate extends MachineIdentityPublic {
  encryptionPrivateKey: string;
  signingPrivateKey: string;
}

export interface MachineState {
  identity?: MachineIdentityPublic;
  projects: Record<string, RegisteredProject>;
  schemaVersion: 1 | typeof SIGNED_IN_SCHEMA_VERSION;
  services?: Record<string, {
    accounts?: string[];
    aliases?: string[];
    default?: string;
  }>;
}

export interface ConnectionMetadata {
  alias: string;
  aliasSource: 'domain' | 'fallback' | 'identity' | 'operator';
  configuredFields: string[];
  createdAt: string;
  hasSession: boolean;
  identity?: string;
  lastVerifiedAt?: string;
  needsLogin?: boolean;
  origin?: ConnectionOrigin;
  updatedAt: string;
}

export interface ConnectionOrigin {
  kind: 'adopted' | 'manual' | 'paired' | 'provider-login';
  recordedAt: string;
  source?: string;
}

export interface ServiceConnections {
  connections: Record<string, ConnectionMetadata>;
  default?: string;
}

export interface MachineConnections {
  schemaVersion: 2;
  services: Record<string, ServiceConnections>;
}

export interface LegacyMachineAccounts {
  schemaVersion: 1;
  services: Record<string, {
    accounts: Record<string, Omit<ConnectionMetadata, 'alias' | 'aliasSource'>>;
    default?: string;
  }>;
}

export interface BinaryPin {
  path: string;
  pinnedAt: string;
  sha256: string;
}

export interface CredentialRecord {
  fields: Record<string, string>;
  importedFrom?: string;
  updatedAt: string;
}

export interface SessionFile {
  contents: string;
  mode: number;
  path: string;
}

export interface SessionBundle {
  files: SessionFile[];
  updatedAt: string;
}

export interface Operation {
  args?: string[];
  cwd?: string;
  environment?: string;
  interface: OperationInterface;
  method?: string;
  path?: string;
  projectId?: string;
  providerId?: string;
}

export interface PolicyDecision {
  classification: OperationClass;
  effect: PolicyEffect;
  matchedRules: string[];
  reason: string;
}

export interface AuditReceipt {
  args?: string[];
  classification: OperationClass;
  completedAt?: string;
  cwd?: string;
  decision: PolicyEffect;
  durationMs?: number;
  errorCode?: string;
  exitCode?: number;
  id: string;
  interface: OperationInterface;
  method?: string;
  path?: string;
  projectId?: string;
  providerId?: string;
  reason: string;
  startedAt: string;
  status: 'completed' | 'failed' | 'started';
}

export interface IpcRequest {
  id: string;
  method: string;
  params?: unknown;
  version: 1;
}

export interface IpcControl {
  event: 'cancel' | 'stdin' | 'stdin-end';
  id: string;
  payload?: string;
}

export interface IpcPingResult {
  build: string;
  pid: number;
  protocol: 1;
  /** Retains compatibility with clients that predate the named protocol field. */
  version: 1;
}

export interface IpcResultEvent {
  event: 'result';
  id: string;
  result: unknown;
}

export interface IpcAcceptedEvent {
  event: 'accepted';
  id: string;
}

export interface IpcOutputEvent {
  data: string;
  encoding: 'base64';
  event: 'stderr' | 'stdout';
  id: string;
}

export interface IpcErrorEvent {
  error: {
    code: string;
    details?: unknown;
    message: string;
  };
  event: 'error';
  id: string;
}

export type IpcEvent = IpcAcceptedEvent | IpcErrorEvent | IpcOutputEvent | IpcResultEvent;

export interface ProviderStatus {
  account: string;
  aliasSource: ConnectionMetadata['aliasSource'];
  connectionId: string;
  configuredFields: string[];
  default: boolean;
  description?: string;
  httpReady: boolean;
  id: string;
  identity?: string;
  invalidFields?: string[];
  isolation: 'brokered' | 'ephemeral-session' | 'injected' | 'none';
  label: string;
  missingFields: string[];
  nativeReady: boolean;
  nativeRemedy?: string;
  origin?: ConnectionOrigin;
  ready: boolean;
  remedy?: string;
  required: boolean;
  signIn: 'interactive' | 'manual';
  sessionReady: boolean;
  state: 'connected' | 'needs-cli' | 'needs-fields' | 'needs-sign-in' | 'needs-trust';
  httpRemedy?: string;
}

export interface ExistingLoginDiscovery {
  available: boolean;
  identity?: string;
  source: string;
}

export interface ServiceStatus {
  accounts: ProviderStatus[];
  description?: string;
  docsUrl?: string;
  id: string;
  label: string;
  projectAccount?: string;
  projectConnectionMissing?: boolean;
  projectConnectionPending?: boolean;
  required: boolean;
  remedy?: string;
  signIn: 'interactive' | 'manual';
  state: 'connected' | 'needs-you' | 'not-connected';
}

export interface HttpRequestParams {
  account?: string;
  approved?: boolean;
  body?: string;
  bodyEncoding?: 'base64' | 'utf8';
  headers?: Record<string, string>;
  method: string;
  path: string;
  projectId?: string;
  providerId: string;
}

export interface NativeRunParams {
  account?: string;
  approved?: boolean;
  args: string[];
  cwd: string;
  projectId?: string;
  providerId: string;
}

export interface ServicePingResult {
  account: string;
  durationMs: number;
  exitCode?: number;
  interface: 'http' | 'native';
  ok: boolean;
  providerId: string;
  status?: number;
  target?: ServicePingTarget;
}

export interface ServicePingTarget {
  label: string;
  value: string | null;
}

export interface ProjectVerificationCheckResult {
  durationMs: number;
  id: string;
  label: string;
  method: 'GET' | 'HEAD';
  ok: boolean;
  path: string;
  status: number;
}

export interface ProjectServiceVerificationResult {
  account: string;
  checks: ProjectVerificationCheckResult[];
  identity?: string;
  ok: boolean;
  ping: ServicePingResult;
  providerId: string;
  target?: ServicePingTarget;
}

export interface ProjectVerificationResult {
  ok: boolean;
  projectId: string;
  services: ProjectServiceVerificationResult[];
}

export interface PairingEnvelope {
  authTag: string;
  ciphertext: string;
  createdAt: string;
  ephemeralPublicKey: string;
  expiresAt: string;
  iv: string;
  kind: 'signed-in-pairing-envelope';
  recipientFingerprint: string;
  salt: string;
  sender: MachineIdentityPublic;
  signature: string;
  version: 1;
}

export interface PairingPayload {
  credentials: Array<{
    account: string;
    fields: Record<string, string>;
    providerId: string;
    updatedAt: string;
  }>;
  skipped: Array<{
    account: string;
    providerId: string;
    reason: string;
  }>;
}
