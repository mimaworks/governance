# @mima-ai/governance

TypeScript SDK for AI governance — push compliance evidence to [Mima](https://mima.ai) from your TypeScript or Node.js application.

One call maps to EU AI Act, ISO 42001, SOC 2, and NIST AI RMF simultaneously.

## When to use this

**Use this SDK** when your TypeScript app code calls AI APIs directly — LangChain chains, batch pipelines, CI scripts, or any workflow where you control the call site.

**Building a TypeScript AI agent?** You don't need this SDK. Use the [MCP server](https://www.npmjs.com/package/@mima-ai/governance-mcp) instead — 4 lines of config, no code changes, any language.

## Install

```bash
npm install @mima-ai/governance
```

Node.js 18+. No runtime dependencies.

## Quick start

```typescript
import { MimaGovernance } from '@mima-ai/governance';

const mima = new MimaGovernance({
  apiKey: process.env.MIMA_API_KEY!,
  systemName: 'customer-support-ai',
});

// Wrap a function — every call attests automatically
const generate = mima.wrap('generate_response', async (prompt: string) => {
  return await llm.complete(prompt);
});

// Push a GRC evidence record
await mima.aiRiskAssessment(
  'customer-support-ai',
  'limited',
  'Customer support question routing',
  {
    intendedPurpose: 'Route customer queries to the correct team',
    impactDomains: ['customer_service'],
    art5SelfAssessment: true,
    assessor: 'alice@example.com',
  },
);
```

## GRC methods

All 11 record types available:

```typescript
await mima.aiRiskAssessment(...)
await mima.modelEvaluation(...)
await mima.humanOversight(...)
await mima.trainingDataGovernance(...)
await mima.incidentReport(...)
await mima.changeEvent(...)
await mima.accessReview(...)
await mima.vendorRisk(...)
await mima.policyAcknowledged(...)
await mima.modelDriftEvent(...)
await mima.governanceReview(...)
```

Each returns `Promise<GrcResult>` with `recordId`, `mappedControls`, and `detail`.

## Four frameworks, one call

| Framework | What it covers |
|---|---|
| EU AI Act | Art. 9–15 risk management, oversight, accuracy obligations |
| ISO 42001 | AI management system controls |
| SOC 2 | CC3.x–CC8.x risk, change, and incident management |
| NIST AI RMF | GOVERN, MAP, MEASURE, MANAGE functions |

## Docs

[docs.mima.ai](https://docs.mima.ai)

## Python SDK

```bash
pip install mima-governance
```
