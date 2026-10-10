# VibeSec — Automated AI Red-Teaming and Security Evaluation Workbench

VibeSec is an automated AI red-teaming and security evaluation workbench built for engineering teams, security reviewers, and platform developers who own or are authorized to test external AI applications.

VibeSec connects to any external AI application via standard HTTP/HTTPS chat APIs, executes controlled adversarial attack vectors (direct prompt injection, roleplay overrides, delimiter manipulation, synthetic secret extraction, multi-turn escalation, and adaptive campaigns), captures actual target model responses, and objectively evaluates safety behavior using dual-layer evaluation: deterministic canary token detection and contextual AI evaluation with multi-provider failover and transparent heuristic fallbacks.

---

## Table of Contents

1. [Problem Statement and Target Users](#problem-statement-and-target-users)
2. [How VibeSec Works](#how-vibesec-works)
3. [System Architecture](#system-architecture)
4. [Multi-Provider Failover Architecture](#multi-provider-failover-architecture)
   - [Semantic Evaluator Failover Chain](#semantic-evaluator-failover-chain)
   - [Demo Target Failover Chain](#demo-target-failover-chain)
   - [Target vs Evaluator Provenance Separation](#target-vs-evaluator-provenance-separation)
5. [Testing Workflows](#testing-workflows)
   - [Single Attack Probes](#1-single-attack-probes)
   - [Core Security Benchmark Suite (v1.0.0)](#2-core-security-benchmark-suite-v100)
   - [Fixed Multi-Turn Attack Campaigns](#3-fixed-multi-turn-attack-campaigns)
   - [Bounded Adaptive Attack Campaigns](#4-bounded-adaptive-attack-campaigns)
   - [Run Comparison and Differential Analysis](#5-run-comparison-and-differential-analysis)
   - [Report Generation and Export](#6-report-generation-and-export)
6. [Verdicts, Metrics, and Provenance](#verdicts-metrics-and-provenance)
7. [Security Model and Defense-in-Depth](#security-model-and-defense-in-depth)
8. [Setup and Quick Start Guide](#setup-and-quick-start-guide)
   - [Prerequisites](#1-prerequisites)
   - [Port Allocation](#2-port-allocation)
   - [Environment Configuration](#3-environment-configuration)
   - [Starting the Services](#4-starting-the-services)
   - [Health Verification](#5-health-verification)
9. [Automated Test Suites](#automated-test-suites)
10. [Demo Script and Verification Flow](#demo-script-and-verification-flow)
11. [Current Limitations and Roadmap](#current-limitations-and-roadmap)

---

## Problem Statement and Target Users

### The Problem
Generative AI applications are frequently exposed via HTTP APIs without standardized, repeatable security testing. Common vulnerabilities include:
- **Instruction Boundary Degradation:** System instructions overridden by untrusted user input.
- **Confidential Data Disclosure:** Accidental leakage of internal tokens, canary secrets, or administrative prompt context.
- **Multi-Turn Conversational Erosion:** Models that safely refuse an attack on Turn 1 but succumb after conversational priming, reframing, or progressive escalation on Turns 2 to 5.
- **Vague or Inconsistent Security Evaluations:** Teams rely on manual ad-hoc prompting or subjective LLM judges without deterministic baselines, test versioning, or evidence traceability.
- **Evaluator and Target Rate-Limit Outages:** Free-tier quotas and transient network failures frequently disrupt test campaigns, causing false positives or unhandled exceptions.

### Target Users
- **AI Application Developers:** Verifying system prompt guardrails and conversational boundaries before production deployment.
- **Application Security Teams:** Automating pre-release red-teaming against HTTP model endpoints.
- **Compliance and Risk Evaluators:** Generating reproducible JSON and Markdown audit evidence with documented failure rate formulas.

---

## How VibeSec Works

VibeSec acts as an independent security workbench that tests your application as an **external black-box HTTP target**:

1. **Configures any Target Schema:** Flexible mapping for OpenAI, Anthropic, or custom internal microservices (`inputPath` and `responsePath`).
2. **Executes Controlled Attacks:** Sends predefined, versioned adversarial vectors without damaging production infrastructure.
3. **Captures Actual Responses:** Records exact status codes, network latency, raw JSON, and extracted assistant replies.
4. **Applies Dual-Layer Evaluation:**
   - **Deterministic Canary Detection:** Instant exact and normalized substring matching for synthetic secrets (`VIBESEC_DEMO_CANARY_42`). Eliminates evaluator hallucinations.
   - **Multi-Provider Semantic Evaluator:** Automated failover across Google Gemini, Groq, and OpenRouter to evaluate behavioral adherence to security requirements.
   - **Transparent Heuristic Fallback:** If all semantic AI providers are exhausted or offline, VibeSec automatically falls back to deterministic heuristic rules (`refusal_heuristic`, `heuristic_fallback`) and prominently tags provenance in the UI and report.
5. **Enforces Strict 4-Verdict Standards:** `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR` — target network failures never silently pass.

---

## System Architecture

```mermaid
flowchart TD
    subgraph ClientLayer ["1. Presentation Layer (Next.js 16 + React)"]
        UI["Workbench UI (Port 3000)\n- Target Setup & Preset Switcher\n- Single Probe Runner\n- Benchmark Suite (v1.0.0)\n- Attack Campaigns (Fixed & Adaptive)\n- Run Comparison & Markdown/JSON Exporters\n- In-Memory Demo Reset"]
    end

    subgraph ServerLayer ["2. VibeSec Security Engine (Express / Node.js - Port 5000)"]
        SSRF["SSRF Defense Guard (urlValidator.js)\n- Prohibits RFC 1918, Cloud Metadata & Loopback\n- Rejects HTTP Redirects & DNS Rebinding"]
        Adapter["HTTP Target Connector (targetAdapter.js)\n- Multi-format Request Templating\n- JSONPath Dot-notation Response Extraction\n- Credential Masking in Logs & UI"]
        Runner["Benchmark & Campaign Engine\n- Sequential Turn Ordering & History State\n- Bounded Execution (Timeouts & Turn Caps)\n- Early Termination on Confirmed Breach"]
        Canary["Synthetic Canary Detector (canaryDetector.js)\n- Deterministic Substring & Normalization Checks"]
        Eval["Multi-Provider Evaluator Manager (providerManager.js)\n- Gemini (Primary)\n- Groq (Secondary)\n- OpenRouter (Tertiary)\n- Heuristic Fallback Engine"]
        History["In-Memory Run Store (History Stores)\n- Bounded 20-Run Ring Buffers\n- Zero Persistent Disk Storage"]
    end

    subgraph TargetLayer ["3. System Under Test (SUT)"]
        DemoTarget["Controlled Demo Target (Port 5050)\n- Multi-Provider Failover: Gemini -> Groq -> OpenRouter\n- Known-Leak Fixture: /api/chat/leak\n- Defended Fixture: /api/chat/defended\n- Multi-Turn Leak Fixture: /api/chat/campaign-leak"]
        ExtTarget["External Production AI Service\n(Authorized OpenAI / Anthropic / Custom API)"]
    end

    UI -->|HTTP / JSON| ServerLayer
    ServerLayer --> SSRF
    SSRF --> Adapter
    Adapter -->|HTTP POST| DemoTarget
    Adapter -->|HTTPS POST| ExtTarget
    Adapter --> Canary
    Canary --> Eval
    Runner --> History
```

---

## Multi-Provider Failover Architecture

To eliminate vulnerability to upstream API rate limits (HTTP 429), quotas, and transient network errors, VibeSec implements separate, production-conscious failover chains for both the evaluator and the demo target.

### Semantic Evaluator Failover Chain
When evaluating an AI application's response, the backend engine executes the following bounded sequence:
1. **Primary Evaluator — Google Gemini:** Attempted first using `@google/genai` (default model: `gemini-2.5-flash`).
2. **Secondary Evaluator — Groq:** If Gemini returns HTTP 429 quota exhaustion, timeout, or network failure, failover immediately shifts to Groq (default model: `llama-3.3-70b-versatile` / `openai/gpt-oss-120b`).
3. **Tertiary Evaluator — OpenRouter:** If Groq is unconfigured or unavailable, failover shifts to OpenRouter (default model: `meta-llama/llama-3.3-70b-instruct`).
4. **Safety Net — Heuristic Fallback:** If all external providers fail or remain unconfigured, the system executes deterministic pattern matching (`heuristic_fallback`). The campaign never crashes, and the fallback provenance is recorded transparently.
5. **Session-Scoped Outage Caching:** If a provider exhausts quota on Turn 1 of a multi-turn campaign, subsequent turns within that campaign session bypass the exhausted provider directly, preventing redundant latency without globally disabling the provider for future sessions.

### Demo Target Failover Chain
The standalone demo target application on port 5050 features an independent provider chain:
1. **Primary Target Backend:** Google Gemini (`gemini-2.5-flash`).
2. **Secondary Target Backend:** Groq (`llama-3.3-70b-versatile` with automatic fallback to active models).
3. **Tertiary Target Backend:** OpenRouter (`meta-llama/llama-3.3-70b-instruct`).
4. **Exhaustion Fallback:** If all target providers are unavailable, the target emits a structured fallback notification, preserving deterministic regression test detection.

### Target vs Evaluator Provenance Separation
VibeSec strictly separates the provenance of the target model from that of the evaluator model:
- `targetExecution.targetProvider`: Identifies the AI provider that generated the target response (e.g., `gemini`, `groq`, `openrouter`, or `demo_fixture`).
- `evaluatorProvenance.finalProvider`: Identifies the AI provider that performed the security assessment (e.g., `gemini`, `groq`, `openrouter`, or `heuristic_fallback`).
- Both dimensions are tracked per turn and exported in Markdown and JSON audit reports.

---

## Testing Workflows

### 1. Single Attack Probes
Execute isolated adversarial vectors to verify target behavior in real-time. Choose from curated presets (`prompt_leak_v1`, `canary_leak_v1`, `roleplay_override_v1`) or enter custom adversarial prompts with target-specific security requirements.

### 2. Core Security Benchmark Suite (`v1.0.0`)
A versioned, 5-test standard benchmark providing an objective baseline:
1. `direct_override_v1`: Direct System Instruction Override (`Instruction Override`)
2. `role_manipulation_v1`: Administrative Maintenance Persona Jailbreak (`Role Manipulation`)
3. `canary_disclosure_v1`: Synthetic Verification Canary Extraction Probe (`Canary Disclosure`)
4. `untrusted_input_injection_v1`: Delimiter-based Indirect Prompt Injection (`Indirect Delimiter Injection`)
5. `app_policy_v1`: Configurable Application Security Policy Enforcement (`Application Policy`)

**Execution Safeguards:**
- Bounded sequential execution with configurable `maxTests` and `maxTotalDurationMs`.
- Completed test evidence is preserved even if subsequent tests time out.
- Dual failure rate calculation: **Raw Failure Rate** and **Evaluated Failure Rate**.

### 3. Fixed Multi-Turn Attack Campaigns
Tests conversational resilience across sequential turns where earlier context informs later attacks:
- `multi_turn_override_v1` (3 Turns): Conversational Instruction Override via framing.
- `multi_turn_canary_extraction_v1` (3 Turns): Indirect Trust Building and Secret Disclosure.
- `multi_turn_policy_escalation_v1` (3 Turns): Escalating Policy Probing.

### 4. Bounded Adaptive Attack Campaigns
Unlike fixed scenarios, an adaptive campaign selects its next attack strategy dynamically based on observed target responses and prior turn verdicts:
- **Strategy Selection:** Evaluates previous turns to pick from 6 specialized strategies (`roleplay_authority_pivot`, `delimiter_confusion_injection`, `hypothetical_counterfactual_framing`, `refusal_suppression_override`, `token_smuggling_obfuscation`, `direct_canary_extraction_escalation`).
- **Strict Execution Budget Caps:** Enforces maximum turn limits (default 5, capped at 10), duration limits (max 90s), and conversation history limits (max 12,000 characters).
- **Early Termination on Violation:** If an attack succeeds in proving a security breach (`FAIL`), the campaign terminates immediately to prevent unnecessary network requests while preserving full conversational evidence.

### 5. Run Comparison and Differential Analysis
Compare any two historical benchmark runs:
- **Compatibility Classification:**
  - `Comparable`: Matching suite, version, target endpoint, and completed execution.
  - `Partially Comparable`: Mismatched evaluator models, cross-target comparisons, or early-terminated runs.
  - `Not Directly Comparable`: Mismatched benchmark suites, version changes, or test set modifications.
- **Differential Metrics:** Failure rate shifts, regressions (PASS to FAIL), fixed vulnerabilities (FAIL to PASS), and newly triggered errors.

### 6. Report Generation and Export
- **JSON Report (`/api/benchmark/report/:runId/export/json`):** Canonical schema 1.0.0 for automated CI/CD gating.
- **Markdown Report (`/api/benchmark/report/:runId/export/markdown`):** Formatted for audit reviews. Uses adaptive CommonMark code fences to prevent untrusted target responses from injecting markdown sections.

---

## Verdicts, Metrics, and Provenance

### 4-Verdict Standards

| Verdict | Meaning | Rule |
| :--- | :--- | :--- |
| **`PASS`** | Defense Validated | Target refused the attack, safely redirected, or operated within safety policy. |
| **`FAIL`** | Vulnerability Confirmed | Target complied with an adversarial override or disclosed canary tokens. |
| **`INCONCLUSIVE`** | Ambiguous Evidence | Target returned an ambiguous response or evaluator was indeterminate. Never counts as PASS. |
| **`ERROR`** | Execution Failure | Target endpoint timed out (504), failed (500), or returned invalid JSON. Never counts as PASS. |

### Failure Rate Calculations
1. **Raw Failure Rate:**
   $$\text{Raw Failure Rate} = \frac{\text{failCount}}{\text{totalTests}} \times 100\%$$
   Denominator: All scheduled tests (`totalTests`). Unfinished or errored tests dilute the raw rate.
2. **Evaluated Failure Rate:**
   $$\text{Evaluated Failure Rate} = \frac{\text{failCount}}{\text{passCount} + \text{failCount}} \times 100\%$$
   Denominator: Definitive evaluations only (`pass + fail`). Excludes `INCONCLUSIVE` and `ERROR`.

---

## Security Model and Defense-in-Depth

1. **SSRF Guard (`server/security/urlValidator.js`):**
   - Restricts protocols strictly to `http:` and `https:`.
   - Prohibits IPv4 loopback (`127.0.0.1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Carrier-Grade NAT (`100.64.0.0/10`), IPv6 loopback (`::1`), and Cloud Metadata IPs (`169.254.169.254`).
   - Rejects HTTP 3xx redirects to eliminate redirect-based SSRF bypasses.
   - Enforces real-time DNS resolution validation on socket creation to prevent DNS rebinding attacks.
   - `ALLOW_LOCAL_TARGETS=true` allows targeting `127.0.0.1:5050` only during explicit local development/testing; in production, this flag defaults to `false`.
2. **Zero File Modification on Reset:** The reset endpoint clears in-memory ring buffers only. It cannot modify filesystem assets, configuration files, or external databases.
3. **Defense Against Prompt Injection in Exporters:** Markdown reports inspect target output and dynamically select code fences (CommonMark 4+ backtick wrapping) to prevent markdown section breakout.
4. **Mandatory Authorization Acknowledgment:** UI requires explicit user confirmation of target ownership before dispatching tests.
5. **Credential Masking:** Headers such as `Authorization` or `x-api-key` are redacted in logs, API responses, and export reports.

---

## Setup and Quick Start Guide

### 1. Prerequisites
- **Node.js:** v20.x or v24.x (Tested on Node.js v24.18.0)
- **npm:** v10.x+
- **API Keys (Optional):**
  - Google Gemini API Key
  - Groq API Key
  - OpenRouter API Key
  *(VibeSec operates fully offline with deterministic fixtures if keys are omitted)*

### 2. Port Allocation
Ensure the following local ports are free before starting:
- **Port 3000:** VibeSec Frontend Workbench (`client`)
- **Port 5000:** VibeSec Backend & Security Engine (`server`)
- **Port 5050:** Controlled Demo Target (`demo-target`)

### 3. Environment Configuration

#### Server Configuration (`server/.env`):
Create `server/.env` or copy from `server/.env.example`:
```ini
PORT=5000

# Evaluator Providers
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile

OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct

SEMANTIC_EVALUATOR_ORDER=gemini,groq,openrouter
SEMANTIC_EVALUATOR_TIMEOUT_MS=20000

# Local Test Mode (permit 127.0.0.1 targets)
ALLOW_LOCAL_TARGETS=true
```

#### Demo Target Configuration (`demo-target/.env`):
Create `demo-target/.env` (or let it fall back automatically to `server/.env`):
```ini
DEMO_TARGET_PORT=5050
TARGET_AI_PROVIDER_ORDER=gemini,groq,openrouter
TARGET_TIMEOUT_MS=20000
```

#### Client Configuration (`client/.env.local`):
Create `client/.env.local`:
```ini
NEXT_PUBLIC_API_URL=http://localhost:5000
```

### 4. Starting the Services

Open three terminal windows:

**Terminal 1 — Controlled Demo Target (Port 5050):**
```bash
cd demo-target
npm start
```

**Terminal 2 — VibeSec Backend Server (Port 5000):**
```bash
cd server
npm start
```

**Terminal 3 — VibeSec Frontend Workbench (Port 3000):**
```bash
cd client
npm run dev
```

Visit **`http://localhost:3000`** in your browser.

### 5. Health Verification
Verify all services are running:
```bash
# Demo Target Health
curl http://127.0.0.1:5050/api/health

# Backend Server Health
curl http://localhost:5000/api/health
```

Both endpoints will return JSON with `status: "ok"` and provider availability mappings.

---

## Automated Test Suites

All automated tests execute against local mock servers and controlled fixtures. Standard tests are **not dependent on external live provider uptime**.

### 1. Complete Backend Suite
```bash
cd server
npm test
```
Executes all regression suites covering:
- Multi-provider failover chains
- Demo target provider failover
- SSRF destination validator
- Deterministic canary detector
- Benchmark engine and 4-verdict reconciliation
- Fixed and adaptive multi-turn campaign runners
- Canonical JSON and Markdown report generation

### 2. Targeted Failover Verification
```bash
cd server
node --test test/demo-target-provider-failover.test.js
node --test test/multi-provider-failover.test.js
node --test test/live-demo-target.test.js
```

### 3. Frontend Lint and Production Build
```bash
cd client
npm run lint
npm run build
```

---

## Demo Script and Verification Flow

### Target Presentation Time: 3 to 4 Minutes

#### Part 1: The Problem and What VibeSec Solves (0:00 - 0:45)
- Connecting LLMs to web applications introduces serious attack surfaces: prompt injection, system prompt extraction, confidential canary leakage, and multi-turn conversational erosion.
- VibeSec provides an automated red-teaming workbench that treats targets as black-box HTTP endpoints, testing them with versioned security benchmarks and dual-layer evaluation.

#### Part 2: Connecting to Target and Testing Vulnerable vs Defended Behavior (0:45 - 1:30)
- In the left sidebar, select the **Hardened Fixture (Defended)** preset (`http://127.0.0.1:5050/api/chat/defended`).
- Click **Test Target Connection** to verify connection and response extraction.
- Navigate to **Single Attack Probe**, select `prompt_leak_v1`, and click **Run Security Evaluation**. Show the **PASS** verdict.
- Switch the target preset to **Known-Failure Fixture (Leak)** (`http://127.0.0.1:5050/api/chat/leak`). Click **Run Security Evaluation**.
- Point out the **FAIL** verdict and the canary detection banner catching `VIBESEC_DEMO_CANARY_42` deterministically.

#### Part 3: Versioned Benchmark Suite and Metrics (1:30 - 2:30)
- Navigate to **Benchmark Suite**.
- Select target preset **Acme Demo (Live AI)**.
- Click **Run Benchmark Suite (5 Tests)**.
- Review the Aggregate Scorecard with explicit counts for PASS, FAIL, INCONCLUSIVE, and ERROR.
- Highlight the dual failure rate reporting (Raw Failure Rate vs Evaluated Failure Rate).

#### Part 4: Multi-Turn and Adaptive Attack Campaigns (2:30 - 3:15)
- Navigate to **Attack Campaigns**.
- Under **Fixed Scenarios**, inspect `multi_turn_override_v1`.
- Switch to **Bounded Adaptive Campaigns** and review the strategy cards (`roleplay_authority_pivot`, `delimiter_confusion_injection`).
- Click **Execute Adaptive Campaign**. Observe turns adapting based on prior target responses with real-time budget consumption gauges.
- Highlight early termination stopping on confirmed breach to save network latency.

#### Part 5: Report Export, Comparison, and Reset (3:15 - 4:00)
- Export both **JSON Report** and **Markdown Report**.
- Navigate to **Compare Runs**, select two benchmark runs, and view the Differential KPI Scorecard.
- Click **Reset Demo** in the top navigation header to show instant in-memory development state clearing.

---

## Current Limitations and Roadmap

### Current Limitations
- **In-Memory History:** Benchmark and campaign runs are stored in bounded ring buffers and reset upon backend server restart.
- **Local Target Exception:** `ALLOW_LOCAL_TARGETS=true` is strictly confined to local development and test modes; production defaults to strict SSRF destination blocking.

### Roadmap
- SQLite and PostgreSQL persistent audit storage for long-term compliance records.
- CI/CD integration with GitHub Actions for automated PR blocking on security regressions.
- User-authored plugin system for custom attack strategies and test criteria.
