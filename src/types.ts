/**
 * Mima AI Governance SDK — TypeScript types.
 *
 * All public interfaces mirror the Python SDK (mima-governance v0.3.x)
 * with idiomatic TypeScript naming (camelCase, no Optional[], etc.).
 */

// ── Record types ─────────────────────────────────────────────────────────────

export type RecordType =
  | 'ai_risk_assessment'
  | 'governance_review'
  | 'model_evaluation'
  | 'training_data_governance'
  | 'human_oversight'
  | 'incident_report'
  | 'change_event'
  | 'access_review'
  | 'vendor_risk'
  | 'model_drift_event'
  | 'policy_acknowledged';

// ── Attestation ───────────────────────────────────────────────────────────────

/** Human principal who authorised the agent execution. */
export interface AuthorisedBy {
  identity: string;
  role?: string;
  sessionId?: string;
}

/** Result returned after a successful attestation push. */
export interface AttestationResult {
  attestationId: string;
  externalVerified: boolean;
  trustTier: string;
  detail: string;
}

/** Result returned after a successful GRC evidence push. */
export interface GrcResult {
  recordId: string;
  recordType: RecordType;
  /** Control IDs earned by this record (e.g. ['EUAIA_ART9', 'ISO42001_6_1']). */
  mappedControls: string[];
  detail: string;
}

// ── Constructor ───────────────────────────────────────────────────────────────

export interface MimaGovernanceOptions {
  /** API key from the Mima dashboard (Settings → API Keys). */
  apiKey: string;
  /** Unique name for the AI system being governed. */
  systemName: string;
  /**
   * Workspace ID. Resolved automatically from the API key if omitted —
   * pass explicitly only when managing multiple workspaces.
   */
  workspaceId?: string;
  /** API base URL. Defaults to https://api.mima.works. */
  baseUrl?: string;
  /**
   * Name for the agent within the system. Defaults to systemName.
   * Useful when one system contains multiple named sub-agents.
   */
  agentName?: string;
  /**
   * Hex-encoded 32-byte HMAC-SHA256 key for GRC record signing.
   * When set, every GRC push includes a client_sig field that auditors
   * can verify to confirm records were created by this SDK instance and
   * not modified in transit.
   */
  signingKey?: string;
  /** Default authorised_by principal for all attestations. */
  authorisedBy?: AuthorisedBy;
  /**
   * Error handling mode.
   * - 'warn'   (default) — console.warn and return an empty result
   * - 'raise'  — throw MimaAttestationError
   * - 'silent' — swallow errors entirely (use only in non-critical paths)
   */
  onError?: 'warn' | 'raise' | 'silent';
  /** Batch flush interval in milliseconds. Default: 30000 (30 s). */
  batchFlushInterval?: number;
  /** Max batch size before an immediate flush. Default: 100. */
  batchMaxSize?: number;
}

// ── wrap() ───────────────────────────────────────────────────────────────────

export interface WrapOptions {
  modelId?: string;
  authorisedBy?: AuthorisedBy;
  /** 'sync' pushes immediately; 'batch' buffers until flush. Default: 'sync'. */
  mode?: 'sync' | 'batch';
}

// ── push() ────────────────────────────────────────────────────────────────────

export interface PushOptions {
  modelId?: string;
  authorisedBy?: AuthorisedBy;
  /** ISO timestamp of execution. Defaults to now. */
  executedAt?: string;
}

// ── trace() ───────────────────────────────────────────────────────────────────

/** Passed to the trace() callback. Call set* methods to attach hashes. */
export interface TraceContext {
  /** Hash the given input and record it. */
  setInput(data: unknown): void;
  /** Hash the given output and record it. */
  setOutput(data: unknown): void;
  /** Override the model ID recorded for this trace. */
  setModelId(modelId: string): void;
}

// ── batch() ───────────────────────────────────────────────────────────────────

/** Passed to the batch() callback. Call add() for each item. */
export interface BatchContext {
  add(
    toolName: string,
    options: {
      input?: unknown;
      output?: unknown;
      inputHash?: string;
      outputHash?: string;
      modelId?: string;
    },
  ): void;
}

// ── GRC method option objects ────────────────────────────────────────────────

export interface AccessReviewOptions {
  reviewedBy: string;
  reviewType?: 'periodic' | 'triggered' | 'initial';
  reason?: string;
}

export interface ChangeEventOptions {
  environment: string;
  system: string;
  changeId?: string;
}

export interface VendorRiskOptions {
  lastReviewed: string;
  findings?: number;
  contacts?: string[];
}

export interface PolicyAcknowledgedOptions {
  version: string;
  systemName?: string;
  acknowledgmentType?: 'initial' | 'renewal' | 'update';
  policyUrl?: string;
  channel?: string;
  sessionId?: string;
}

export interface IncidentReportOptions {
  description: string;
  affectedSystems: string[];
  detectedAt?: string;
  authorityNotifiedAt?: string;
}

export interface AiRiskAssessmentOptions {
  intendedPurpose: string;
  impactDomains: string[];
  art5SelfAssessment: boolean;
  assessor: string;
  /**
   * Required when riskTier is 'high'. One of:
   * biometric_identification | critical_infrastructure | education_vocational |
   * employment_management | essential_services | law_enforcement |
   * migration_border | justice_democratic | not_annex_iii
   */
  annexIiiCategory?: string;
  assessmentDate?: string;
  technicalDocUrl?: string;
  trainingDataUrl?: string;
  environment?: 'production' | 'staging' | 'development';
  systemVersion?: string;
  notes?: string;
}

export interface TrainingDataGovernanceOptions {
  biasChecksPerformed: boolean;
  approvedBy: string;
  dataSources: string[];
  dataCategories: string[];
  approvalDate?: string;
  knownLimitations?: string;
}

export interface ModelEvaluationOptions {
  evaluatedBy: string;
  evaluationType?: 'initial' | 'quarterly' | 'triggered';
  biasMetrics?: Record<string, number>;
  robustnessScore?: number;
  passedThreshold?: boolean;
  evaluationDate?: string;
  notes?: string;
}

export interface HumanOversightOptions {
  reviewer: string;
  rationale?: string;
  modelId?: string;
  /** Defaults to true when aiRecommendation !== humanDecision. */
  override?: boolean;
}

export interface ModelDriftEventOptions {
  driftType?: 'performance' | 'data' | 'concept';
  detectedBy: string;
  actionTaken?: string;
  detectionDate?: string;
}

export interface GovernanceReviewOptions {
  frameworksReviewed: string[];
  /** Readiness score 0–100. */
  overallReadiness: number;
  actionItems?: number;
  reviewDate?: string;
  notes?: string;
}
