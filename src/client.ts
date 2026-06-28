/**
 * Mima AI Governance SDK — TypeScript client.
 *
 * Compatible with Node.js 18+ (uses native fetch and crypto).
 * Mirrors the Python SDK (mima-governance v0.3.x) with idiomatic TypeScript.
 */

import { createHash, createHmac } from 'node:crypto';
import type {
  MimaGovernanceOptions,
  AttestationResult,
  GrcResult,
  RecordType,
  AuthorisedBy,
  WrapOptions,
  PushOptions,
  TraceContext,
  BatchContext,
  AccessReviewOptions,
  ChangeEventOptions,
  VendorRiskOptions,
  PolicyAcknowledgedOptions,
  IncidentReportOptions,
  AiRiskAssessmentOptions,
  TrainingDataGovernanceOptions,
  ModelEvaluationOptions,
  HumanOversightOptions,
  ModelDriftEventOptions,
  GovernanceReviewOptions,
} from './types.js';

// ── Internal record types ─────────────────────────────────────────────────────

interface AttestationRecord {
  toolName: string;
  inputHash: string;
  outputHash: string;
  modelId?: string;
  executedAt: string;
  authorisedBy?: AuthorisedBy;
}

interface GrcRecord {
  recordType: string;
  payload: Record<string, unknown>;
  systemName: string;
  identity?: string;
  resource?: string;
  environment?: string;
  occurredAt: string;
}

// ── Wire API response shapes ──────────────────────────────────────────────────

interface AttestationApiResponse {
  attestation_id: string;
  external_verified: boolean;
  trust_tier: string;
  detail: string;
}

interface GrcApiResponse {
  record_id: string;
  record_type: string;
  mapped_controls?: string[];
}

// ── Error ─────────────────────────────────────────────────────────────────────

export class MimaAttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MimaAttestationError';
  }
}

// ── Trace context impl ────────────────────────────────────────────────────────

class TraceContextImpl implements TraceContext {
  _inputHash?: string;
  _outputHash?: string;
  _modelId?: string;

  setInput(data: unknown): void {
    this._inputHash = sha256(stableStringify(data));
  }
  setOutput(data: unknown): void {
    this._outputHash = sha256(stableStringify(data));
  }
  setModelId(modelId: string): void {
    this._modelId = modelId;
  }
}

// ── Batch context impl ────────────────────────────────────────────────────────

class BatchContextImpl implements BatchContext {
  constructor(private readonly _client: MimaGovernance) {}

  add(
    toolName: string,
    options: {
      input?: unknown;
      output?: unknown;
      inputHash?: string;
      outputHash?: string;
      modelId?: string;
    },
  ): void {
    const record: AttestationRecord = {
      toolName,
      inputHash: options.inputHash ?? sha256(stableStringify(options.input)),
      outputHash: options.outputHash ?? sha256(stableStringify(options.output)),
      modelId: options.modelId,
      executedAt: new Date().toISOString(),
      authorisedBy: this._client.authorisedBy,
    };
    this._client._enqueue(record);
  }
}

// ── Main client ───────────────────────────────────────────────────────────────

export class MimaGovernance {
  private readonly apiKey: string;
  private readonly systemName: string;
  private workspaceId?: string;
  private readonly baseUrl: string;
  private readonly agentName: string;
  private readonly signingKey?: string;
  readonly authorisedBy?: AuthorisedBy;
  private readonly onError: 'warn' | 'raise' | 'silent';
  private readonly batchFlushInterval: number;
  private readonly batchMaxSize: number;

  private readonly batchQueue: AttestationRecord[] = [];
  private batchTimer?: NodeJS.Timeout;
  private closed = false;

  constructor(options: MimaGovernanceOptions) {
    this.apiKey = options.apiKey;
    this.systemName = options.systemName;
    this.workspaceId = options.workspaceId;
    this.baseUrl = (options.baseUrl ?? 'https://api.mima.ai').replace(/\/$/, '');
    this.agentName = options.agentName ?? options.systemName;
    this.signingKey = options.signingKey;
    this.authorisedBy = options.authorisedBy;
    this.onError = options.onError ?? 'warn';
    this.batchFlushInterval = options.batchFlushInterval ?? 30_000;
    this.batchMaxSize = options.batchMaxSize ?? 100;

    // Flush before the process exits.
    process.once('beforeExit', () => void this.close());
  }

  // ── Workspace ID resolution ──────────────────────────────────────────────

  private async _ensureWs(): Promise<string> {
    if (!this.workspaceId) {
      this.workspaceId = await this._resolveWorkspaceId();
    }
    if (!this.workspaceId) {
      throw new MimaAttestationError(
        'workspaceId not set and could not be resolved automatically — ' +
          'pass workspaceId, set MIMA_WORKSPACE_ID, or run `mima login`',
      );
    }
    return this.workspaceId;
  }

  private async _resolveWorkspaceId(): Promise<string | undefined> {
    // Check env var first.
    const fromEnv = process.env['MIMA_WORKSPACE_ID'];
    if (fromEnv) return fromEnv;
    try {
      const resp = await this._fetch('GET', '/api/me');
      if (resp.ok) {
        const data = (await resp.json()) as { workspace_id?: string };
        return data.workspace_id;
      }
    } catch {
      // swallow — handled downstream
    }
    return undefined;
  }

  // ── wrap() — function-level attestation ─────────────────────────────────

  /**
   * Wrap a function so every call automatically attests execution.
   * The wrapped function always returns a Promise.
   *
   * ```ts
   * const classify = mima.wrap('classify_document', async (doc: string) => {
   *   return await model.classify(doc);
   * });
   *
   * const label = await classify(myDoc); // attests automatically
   * ```
   */
  wrap<TArgs extends unknown[], TReturn>(
    toolName: string,
    fn: (...args: TArgs) => TReturn | Promise<TReturn>,
    options: WrapOptions = {},
  ): (...args: TArgs) => Promise<TReturn> {
    return async (...args: TArgs): Promise<TReturn> => {
      const inputHash = sha256(stableStringify(args));
      const result = await Promise.resolve(fn(...args));
      const outputHash = sha256(stableStringify(result));

      const record: AttestationRecord = {
        toolName,
        inputHash,
        outputHash,
        modelId: options.modelId,
        executedAt: new Date().toISOString(),
        authorisedBy: options.authorisedBy ?? this.authorisedBy,
      };

      if (options.mode === 'batch') {
        this._enqueue(record);
      } else {
        await this._pushSync(record);
      }

      return result;
    };
  }

  // ── push() — explicit attestation ───────────────────────────────────────

  /**
   * Push a pre-computed attestation record.
   * Use when you already have input/output hashes (e.g. from a pipeline step).
   *
   * ```ts
   * await mima.push('generate_report', inputHash, outputHash, {
   *   modelId: 'claude-opus-4-6',
   * });
   * ```
   */
  async push(
    toolName: string,
    inputHash: string,
    outputHash: string,
    options: PushOptions = {},
  ): Promise<AttestationResult> {
    const record: AttestationRecord = {
      toolName,
      inputHash,
      outputHash,
      modelId: options.modelId,
      executedAt: options.executedAt ?? new Date().toISOString(),
      authorisedBy: options.authorisedBy ?? this.authorisedBy,
    };
    return this._pushSync(record);
  }

  // ── trace() — explicit hash capture ─────────────────────────────────────

  /**
   * Run a callback with a trace context. Call ctx.setInput/setOutput
   * to record hashes manually.
   *
   * ```ts
   * const result = await mima.trace('run_pipeline', async (ctx) => {
   *   ctx.setInput(inputDocs);
   *   const output = await pipeline.run(inputDocs);
   *   ctx.setOutput(output);
   *   ctx.setModelId('claude-opus-4-6');
   *   return output;
   * });
   * ```
   */
  async trace<T>(
    toolName: string,
    fn: (ctx: TraceContext) => T | Promise<T>,
  ): Promise<T> {
    const ctx = new TraceContextImpl();
    const result = await Promise.resolve(fn(ctx));

    const record: AttestationRecord = {
      toolName,
      inputHash: ctx._inputHash ?? sha256(''),
      outputHash: ctx._outputHash ?? sha256(''),
      modelId: ctx._modelId,
      executedAt: new Date().toISOString(),
      authorisedBy: this.authorisedBy,
    };
    await this._pushSync(record);
    return result;
  }

  // ── batch() — buffered multi-record push ─────────────────────────────────

  /**
   * Buffer multiple attestations then flush in a single request.
   *
   * ```ts
   * await mima.batch(async (b) => {
   *   for (const item of queue) {
   *     const result = await processItem(item);
   *     b.add('process_item', { input: item, output: result });
   *   }
   * });
   * ```
   */
  async batch(fn: (ctx: BatchContext) => void | Promise<void>): Promise<void> {
    const ctx = new BatchContextImpl(this);
    await Promise.resolve(fn(ctx));
    await this._flushBatch();
  }

  // ── GRC: accessReview ────────────────────────────────────────────────────

  /** Record a periodic or triggered access review decision. */
  async accessReview(
    user: string,
    resource: string,
    granted: boolean,
    options: AccessReviewOptions,
  ): Promise<GrcResult> {
    const payload: Record<string, unknown> = {
      user,
      resource,
      granted,
      reviewed_by: options.reviewedBy,
      review_type: options.reviewType ?? 'periodic',
    };
    if (options.reason !== undefined) payload['reason'] = options.reason;
    return this._pushGrc({
      recordType: 'access_review',
      payload,
      systemName: this.systemName,
      identity: user,
      resource,
      occurredAt: now(),
    });
  }

  // ── GRC: changeEvent ─────────────────────────────────────────────────────

  /** Record a system change event (deploy, config change, prompt update, etc.). */
  async changeEvent(
    type: string,
    by: string,
    description: string,
    options: ChangeEventOptions,
  ): Promise<GrcResult> {
    const payload: Record<string, unknown> = {
      type,
      by,
      description,
      environment: options.environment,
      system: options.system,
    };
    if (options.changeId !== undefined) payload['change_id'] = options.changeId;
    return this._pushGrc({
      recordType: 'change_event',
      payload,
      systemName: this.systemName,
      identity: by,
      resource: options.system,
      environment: options.environment,
      occurredAt: now(),
    });
  }

  // ── GRC: vendorRisk ──────────────────────────────────────────────────────

  /** Record a vendor risk assessment. */
  async vendorRisk(
    vendor: string,
    tier: 'critical' | 'high' | 'medium' | 'low',
    options: VendorRiskOptions,
  ): Promise<GrcResult> {
    const payload: Record<string, unknown> = {
      vendor,
      tier,
      last_reviewed: options.lastReviewed,
      findings: options.findings ?? 0,
    };
    if (options.contacts !== undefined) payload['contacts'] = options.contacts;
    return this._pushGrc({
      recordType: 'vendor_risk',
      payload,
      systemName: this.systemName,
      resource: vendor,
      occurredAt: now(),
    });
  }

  // ── GRC: policyAcknowledged ──────────────────────────────────────────────

  /** Record that a user has acknowledged a policy version. */
  async policyAcknowledged(
    policy: string,
    user: string,
    options: PolicyAcknowledgedOptions,
  ): Promise<GrcResult> {
    const ackType = options.acknowledgmentType ?? 'initial';
    const validTypes = ['initial', 'renewal', 'update'];
    if (!validTypes.includes(ackType)) {
      throw new Error(`acknowledgmentType must be one of ${validTypes.join(', ')}, got '${ackType}'`);
    }
    const policySlug = policy.toLowerCase().replace(/ /g, '-');
    const versionedResource = `policy:${policySlug}:${options.version}`;
    const payload: Record<string, unknown> = {
      decision: 'acknowledged',
      policy_name: policy,
      policy_version: options.version,
      acknowledgment_type: ackType,
      channel: options.channel ?? 'in-app',
    };
    if (options.policyUrl !== undefined) payload['policy_url'] = options.policyUrl;
    if (options.sessionId !== undefined) payload['session_id'] = options.sessionId;
    return this._pushGrc({
      recordType: 'policy_acknowledged',
      payload,
      systemName: options.systemName ?? this.systemName,
      identity: user,
      resource: versionedResource,
      occurredAt: now(),
    });
  }

  // ── GRC: incidentReport ──────────────────────────────────────────────────

  /** Record a security or AI incident. */
  async incidentReport(
    title: string,
    severity: 'critical' | 'high' | 'medium' | 'low',
    options: IncidentReportOptions,
  ): Promise<GrcResult> {
    const payload: Record<string, unknown> = {
      title,
      severity,
      description: options.description,
      affected_systems: options.affectedSystems,
    };
    if (options.authorityNotifiedAt !== undefined) {
      payload['authority_notified_at'] = options.authorityNotifiedAt;
    }
    return this._pushGrc({
      recordType: 'incident_report',
      payload,
      systemName: this.systemName,
      occurredAt: options.detectedAt ?? now(),
    });
  }

  // ── GRC: aiRiskAssessment ────────────────────────────────────────────────

  /** Record an AI system risk classification (Art. 9 EUAIA). */
  async aiRiskAssessment(
    systemName: string,
    riskTier: 'unacceptable' | 'high' | 'limited' | 'minimal',
    useCase: string,
    options: AiRiskAssessmentOptions,
  ): Promise<GrcResult> {
    if (riskTier === 'high' && !options.annexIiiCategory) {
      throw new Error('annexIiiCategory is required for high-risk systems');
    }
    const payload: Record<string, unknown> = {
      risk_level: riskTier,
      risk_summary: useCase,
      intended_purpose: options.intendedPurpose,
      impact_domains: options.impactDomains,
      art5_self_assessment: options.art5SelfAssessment,
    };
    if (options.annexIiiCategory !== undefined) payload['annex_iii_category'] = options.annexIiiCategory;
    if (options.systemVersion !== undefined) payload['system_version'] = options.systemVersion;
    if (options.technicalDocUrl !== undefined) payload['technical_doc_url'] = options.technicalDocUrl;
    if (options.trainingDataUrl !== undefined) payload['training_data_url'] = options.trainingDataUrl;
    if (options.notes !== undefined) payload['notes'] = options.notes;
    return this._pushGrc({
      recordType: 'ai_risk_assessment',
      payload,
      systemName,
      identity: options.assessor,
      resource: systemName,
      environment: options.environment ?? 'production',
      occurredAt: options.assessmentDate ?? now(),
    });
  }

  // ── GRC: trainingDataGovernance ──────────────────────────────────────────

  /** Record governance approval for a training dataset. */
  async trainingDataGovernance(
    modelId: string,
    datasetId: string,
    recordCount: number,
    options: TrainingDataGovernanceOptions,
  ): Promise<GrcResult> {
    const payload: Record<string, unknown> = {
      model_id: modelId,
      dataset_id: datasetId,
      record_count: recordCount,
      bias_checks_performed: options.biasChecksPerformed,
      approved_by: options.approvedBy,
      data_sources: options.dataSources,
      data_categories: options.dataCategories,
    };
    if (options.knownLimitations !== undefined) payload['known_limitations'] = options.knownLimitations;
    return this._pushGrc({
      recordType: 'training_data_governance',
      payload,
      systemName: this.systemName,
      resource: datasetId,
      identity: options.approvedBy,
      occurredAt: options.approvalDate ?? now(),
    });
  }

  // ── GRC: modelEvaluation ─────────────────────────────────────────────────

  /** Record a model evaluation run. */
  async modelEvaluation(
    modelId: string,
    dataset: string,
    accuracy: number,
    options: ModelEvaluationOptions,
  ): Promise<GrcResult> {
    const evalType = options.evaluationType ?? 'quarterly';
    const validTypes = ['initial', 'quarterly', 'triggered'];
    if (!validTypes.includes(evalType)) {
      throw new Error(`evaluationType must be one of ${validTypes.join(', ')}, got '${evalType}'`);
    }
    const payload: Record<string, unknown> = {
      model_id: modelId,
      dataset,
      accuracy,
      evaluated_by: options.evaluatedBy,
      evaluation_type: evalType,
    };
    if (options.biasMetrics !== undefined) payload['bias_metrics'] = options.biasMetrics;
    if (options.robustnessScore !== undefined) payload['robustness_score'] = options.robustnessScore;
    if (options.passedThreshold !== undefined) payload['passed_threshold'] = options.passedThreshold;
    if (options.notes !== undefined) payload['notes'] = options.notes;
    return this._pushGrc({
      recordType: 'model_evaluation',
      payload,
      systemName: this.systemName,
      resource: modelId,
      identity: options.evaluatedBy,
      occurredAt: options.evaluationDate ?? now(),
    });
  }

  // ── GRC: humanOversight ──────────────────────────────────────────────────

  /** Record a human review of an AI decision. */
  async humanOversight(
    decisionId: string,
    aiRecommendation: string,
    humanDecision: string,
    options: HumanOversightOptions,
  ): Promise<GrcResult> {
    const didOverride = options.override ?? aiRecommendation !== humanDecision;
    const payload: Record<string, unknown> = {
      decision_id: decisionId,
      ai_recommendation: aiRecommendation,
      human_decision: humanDecision,
      reviewer: options.reviewer,
      override: didOverride,
    };
    if (options.rationale !== undefined) payload['rationale'] = options.rationale;
    if (options.modelId !== undefined) payload['model_id'] = options.modelId;
    return this._pushGrc({
      recordType: 'human_oversight',
      payload,
      systemName: this.systemName,
      resource: decisionId,
      identity: options.reviewer,
      occurredAt: now(),
    });
  }

  // ── GRC: modelDriftEvent ─────────────────────────────────────────────────

  /** Record a model drift detection event. */
  async modelDriftEvent(
    modelId: string,
    metric: string,
    baseline: number,
    current: number,
    threshold: number,
    options: ModelDriftEventOptions,
  ): Promise<GrcResult> {
    const driftType = options.driftType ?? 'performance';
    const validTypes = ['performance', 'data', 'concept'];
    if (!validTypes.includes(driftType)) {
      throw new Error(`driftType must be one of ${validTypes.join(', ')}, got '${driftType}'`);
    }
    const payload: Record<string, unknown> = {
      model_id: modelId,
      metric,
      baseline,
      current,
      threshold,
      drift_type: driftType,
      detected_by: options.detectedBy,
    };
    if (options.actionTaken !== undefined) payload['action_taken'] = options.actionTaken;
    return this._pushGrc({
      recordType: 'model_drift_event',
      payload,
      systemName: this.systemName,
      resource: modelId,
      identity: options.detectedBy,
      occurredAt: options.detectionDate ?? now(),
    });
  }

  // ── GRC: governanceReview ────────────────────────────────────────────────

  /** Record a governance readiness review. */
  async governanceReview(
    reviewedBy: string,
    reportType: string,
    options: GovernanceReviewOptions,
  ): Promise<GrcResult> {
    if (options.overallReadiness < 0 || options.overallReadiness > 100) {
      throw new Error(`overallReadiness must be 0–100, got '${options.overallReadiness}'`);
    }
    const payload: Record<string, unknown> = {
      reviewed_by: reviewedBy,
      report_type: reportType,
      frameworks_reviewed: options.frameworksReviewed,
      overall_readiness: options.overallReadiness,
      action_items: options.actionItems ?? 0,
    };
    if (options.notes !== undefined) payload['notes'] = options.notes;
    return this._pushGrc({
      recordType: 'governance_review',
      payload,
      systemName: this.systemName,
      identity: reviewedBy,
      occurredAt: options.reviewDate ?? now(),
    });
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  /**
   * Flush any pending batch records and close the client.
   * Call this at the end of long-running processes or serverless invocations.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this._flushBatch();
  }

  // ── Internal: sync push ──────────────────────────────────────────────────

  private async _pushSync(record: AttestationRecord): Promise<AttestationResult> {
    const payload = this._buildPayload(record);
    const ws = await this._ensureWs();

    try {
      let resp = await this._fetch(
        'POST',
        `/api/workspaces/${ws}/governance/attestations/external`,
        payload,
      );

      if (resp.status === 429) {
        const retryAfter = parseInt(resp.headers.get('retry-after') ?? '5', 10);
        await sleep(Math.min(retryAfter * 1_000, 60_000));
        resp = await this._fetch(
          'POST',
          `/api/workspaces/${ws}/governance/attestations/external`,
          payload,
        );
      }

      if (!resp.ok) {
        return this._handleError(
          `Attestation push failed: HTTP ${resp.status} — ${await resp.text()}`,
        );
      }

      const data = (await resp.json()) as AttestationApiResponse;
      return {
        attestationId: data.attestation_id,
        externalVerified: data.external_verified,
        trustTier: data.trust_tier,
        detail: data.detail,
      };
    } catch (err) {
      if (err instanceof MimaAttestationError) throw err;
      return this._handleError(`Attestation push error: ${err}`);
    }
  }

  // ── Internal: GRC push ───────────────────────────────────────────────────

  private async _pushGrc(record: GrcRecord): Promise<GrcResult> {
    const payload = this._buildGrcPayload(record);
    const ws = await this._ensureWs();

    try {
      const resp = await this._fetch(
        'POST',
        `/api/workspaces/${ws}/governance/grc/evidence`,
        payload,
      );

      if (!resp.ok) {
        return this._handleGrcError(
          `GRC push failed: HTTP ${resp.status} — ${await resp.text()}`,
          record,
        );
      }

      const data = (await resp.json()) as GrcApiResponse;
      return {
        recordId: data.record_id,
        recordType: data.record_type as RecordType,
        mappedControls: data.mapped_controls ?? [],
        detail: 'ok',
      };
    } catch (err) {
      if (err instanceof MimaAttestationError) throw err;
      return this._handleGrcError(`GRC push error: ${err}`, record);
    }
  }

  // ── Internal: payload builders ───────────────────────────────────────────

  private _buildPayload(record: AttestationRecord): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      system_name: this.systemName,
      agent_name: this.agentName,
      tool_name: record.toolName,
      input_hash: record.inputHash,
      output_hash: record.outputHash,
      schema_version: 2,
      executed_at: record.executedAt,
    };
    if (record.modelId !== undefined) payload['model_id'] = record.modelId;
    if (record.authorisedBy !== undefined) {
      const ab: Record<string, string> = { identity: record.authorisedBy.identity };
      if (record.authorisedBy.role !== undefined) ab['role'] = record.authorisedBy.role;
      if (record.authorisedBy.sessionId !== undefined) ab['session_id'] = record.authorisedBy.sessionId;
      payload['authorised_by'] = ab;
    }
    return payload;
  }

  private _buildGrcPayload(record: GrcRecord): Record<string, unknown> {
    const wire: Record<string, unknown> = {
      record_type: record.recordType,
      payload: record.payload,
      system_name: record.systemName,
      occurred_at: record.occurredAt,
    };
    if (record.identity !== undefined) wire['identity'] = record.identity;
    if (record.resource !== undefined) wire['resource'] = record.resource;
    if (record.environment !== undefined) wire['environment'] = record.environment;

    if (this.signingKey && this.workspaceId) {
      wire['client_sig'] = this._signGrc(record, wire);
      wire['client_sig_algo'] = 'hmac-sha256';
    }
    return wire;
  }

  private _signGrc(record: GrcRecord, wire: Record<string, unknown>): string {
    // Canonical message matches the Python SDK exactly:
    // json.dumps({...}, sort_keys=True, separators=(',', ':'))
    const canonical = sortedStringify({
      occurred_at: wire['occurred_at'] ?? '',
      payload: record.payload,
      record_type: record.recordType,
      system_name: record.systemName,
      workspace_id: this.workspaceId ?? '',
    });
    return createHmac('sha256', Buffer.from(this.signingKey!, 'hex'))
      .update(canonical)
      .digest('hex');
  }

  // ── Internal: batch queue ────────────────────────────────────────────────

  _enqueue(record: AttestationRecord): void {
    this.batchQueue.push(record);
    if (this.batchQueue.length >= this.batchMaxSize) {
      void this._flushBatch();
      return;
    }
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(() => void this._flushBatch(), this.batchFlushInterval);
    }
  }

  private async _flushBatch(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }
    const records = this.batchQueue.splice(0);
    if (!records.length) return;

    const payloads = records.map((r) => this._buildPayload(r));

    let ws: string;
    try {
      ws = await this._ensureWs();
    } catch {
      return; // Cannot flush without workspace ID
    }

    try {
      const resp = await this._fetch(
        'POST',
        `/api/workspaces/${ws}/governance/attestations/batch`,
        { records: payloads },
      );

      if (resp.status === 404) {
        // Server doesn't support batch yet — fall back to per-record.
        await Promise.all(records.map((r) => this._pushSync(r)));
        return;
      }

      if (!resp.ok) {
        this._handleError(`Batch push failed: HTTP ${resp.status}`);
      }
    } catch (err) {
      this._handleError(`Batch push error: ${err}`);
    }
  }

  // ── Internal: error handling ─────────────────────────────────────────────

  private _handleError(message: string): AttestationResult {
    if (this.onError === 'raise') throw new MimaAttestationError(message);
    if (this.onError === 'warn') console.warn(`[mima-governance] ${message}`);
    return { attestationId: '', externalVerified: false, trustTier: 'declared', detail: message };
  }

  private _handleGrcError(message: string, record: GrcRecord): GrcResult {
    if (this.onError === 'raise') throw new MimaAttestationError(message);
    if (this.onError === 'warn') console.warn(`[mima-governance] ${message}`);
    return { recordId: '', recordType: record.recordType as RecordType, mappedControls: [], detail: message };
  }

  // ── Internal: HTTP ───────────────────────────────────────────────────────

  private async _fetch(method: string, path: string, body?: unknown): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      return await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'User-Agent': 'mima-governance-ts/0.1.0',
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function now(): string {
  return new Date().toISOString();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Deterministic JSON stringify with sorted keys at all levels.
 * Matches Python's json.dumps(sort_keys=True, separators=(',', ':')) exactly,
 * ensuring cross-language HMAC signature compatibility.
 */
function sortedStringify(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(sortedStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + sortedStringify(obj[k])).join(',') + '}';
}

/**
 * Stable stringify for attestation input/output hashing.
 * Uses the same sorted-keys approach to ensure consistent hashes
 * regardless of object key insertion order.
 */
function stableStringify(value: unknown): string {
  try {
    return sortedStringify(value);
  } catch {
    return String(value);
  }
}
