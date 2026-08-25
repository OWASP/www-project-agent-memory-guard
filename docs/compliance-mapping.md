# OWASP Agent Memory Guard: Regulatory Compliance Mapping

**Author:** Vaishnavi Gudur, OWASP Agent Memory Guard Project Lead  
**Version:** 1.1  
**Date:** August 2026  
**Measurement basis:** AMG 0.2.2 benchmark suite (55 cases) - see §0  
**Applicable Standards:** NIST AI RMF 1.0 (AI 100-1), EU AI Act (Regulation 2024/1689)

---

## Executive Summary

This document maps the controls and capabilities provided by OWASP Agent Memory Guard (AMG) to the requirements of two major AI governance frameworks: the NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0) and the European Union Artificial Intelligence Act (EU AI Act). The mapping demonstrates how AMG's runtime memory poisoning detection directly supports organizational compliance with these frameworks, particularly in the areas of security, robustness, and risk management for AI systems that employ persistent memory.

Organizations deploying AI agents with persistent memory stores face a novel class of integrity risk — memory poisoning — that is explicitly recognized in the OWASP Top 10 for Agentic Applications (ASI06) [1] and MITRE ATLAS (AML.T0080.000) [2]. AMG provides the technical controls necessary to address these risks within the structured governance approaches mandated by both NIST and EU regulatory frameworks.

---

## 0. Basis of measurement

Every quantitative claim in this document resolves to one of two artifacts. Nothing here is estimated, extrapolated, or rounded up.

| Figure | Value | Source | Scope and limits |
|--------|-------|--------|------------------|
| Recall (detection rate) | 92.5% | `benchmarks/results/benchmark_results.json`, produced by `benchmarks/security_benchmark.py` [7] | 55 cases: 40 attack payloads, 15 benign. Measured on AMG 0.2.2. |
| Precision | 100% | same | No benign case was flagged. |
| F1 | 0.961 | same | same |
| False positive rate | 0% | same | On this corpus only. Not a general claim. |
| Median added latency | 62 µs | `benchmarks/results/benchmark_report.md` [7] | Per memory operation, single-process, no network memory backend. |
| Public attack corpus | 75 examples | HuggingFace [4] | 10 each across six threat categories, plus 15 benign. Distinct from, and larger than, the 55-case benchmark suite. |

**What these numbers do not establish.** The corpus is representative, not exhaustive, and was authored by the project. A 92.5% recall figure on 55 authored cases is evidence that the detectors work on known attack shapes; it is not a measure of performance against an adaptive adversary or against payload families the corpus does not contain. Organizations citing these figures in regulatory documentation should cite them with the corpus size attached, and should run the benchmark against their own attack corpus before relying on the number in an accuracy declaration.

**Reproducing them.** `python benchmarks/security_benchmark.py` regenerates every figure in this table from source. Re-run it against the version you deploy; these values are pinned to 0.2.2 and will move.

---

## 1. NIST AI Risk Management Framework (AI RMF 1.0) Mapping

The NIST AI RMF organizes risk management into four core functions: **Govern**, **Map**, **Measure**, and **Manage** [3]. Each function contains categories and subcategories that describe outcomes for trustworthy AI. The following table maps AMG capabilities to the most relevant subcategories.

### 1.1 GOVERN Function

The Govern function establishes organizational culture, policies, and accountability for AI risk management. AMG supports governance by providing enforceable security policies for memory operations.

| Subcategory | Requirement | AMG Contribution |
|-------------|-------------|------------------|
| Govern 1.1 | Legal and regulatory requirements involving AI are understood, managed, and documented. | AMG's policy engine enables organizations to codify memory security requirements as enforceable rules, creating auditable documentation of compliance controls. |
| Govern 1.2 | Characteristics of trustworthy AI are integrated into organizational policies. | AMG operationalizes the "Secure and Resilient" trustworthiness characteristic by providing runtime validation of memory integrity — a core security property for AI agents. |
| Govern 1.5 | Ongoing monitoring and periodic review of risk management outcomes. | AMG's continuous scanning provides real-time monitoring data. Integration with observability platforms (Langfuse, Arize Phoenix, LangSmith) enables periodic review dashboards. |
| Govern 4.3 | Organizational practices enable AI testing, incident identification, and information sharing. | AMG generates structured detection events with threat categorization, enabling incident identification and cross-team information sharing about memory poisoning attempts. |
| Govern 6.1 | Policies address AI risks from third-party entities. | AMG scans all memory content regardless of source (user input, tool output, retrieved documents), mitigating supply-chain risks from third-party data entering the memory store. |
| Govern 6.2 | Contingency processes handle failures in third-party AI systems. | AMG's blocking mode provides a contingency control — when third-party components produce poisoned outputs, AMG prevents them from persisting in the agent's memory. |

### 1.2 MAP Function

The Map function establishes context and identifies risks. AMG contributes by characterizing the memory poisoning attack surface.

| Subcategory | Requirement | AMG Contribution |
|-------------|-------------|------------------|
| Map 1.1 | Intended purposes, context-specific risks, and deployment settings are documented. | AMG's threat taxonomy (injection, exfiltration, privilege escalation, persistence, tool abuse, cross-task contamination) provides a structured vocabulary for documenting memory-specific risks in deployment contexts. |
| Map 1.6 | System requirements address socio-technical implications. | AMG enables the requirement "the system shall validate all memory writes for poisoning patterns" — a concrete, testable security requirement for agent architectures. |
| Map 2.2 | AI system knowledge limits and human oversight are documented. | AMG's detection confidence scores communicate the system's knowledge limits — what it can and cannot detect — enabling informed human oversight decisions. |
| Map 2.3 | Scientific integrity and TEVV considerations are documented. | AMG publishes a labeled attack corpus (75 examples across six threat categories plus benign controls, on HuggingFace [4]) and a reproducible 55-case benchmark suite in-repo [7]. Measured recall is 92.5% at 100% precision (F1 0.961). See §0 for the basis of every figure in this document. |
| Map 4.1 | Approaches for mapping legal risks of third-party components are documented. | AMG identifies when third-party data (tool outputs, RAG retrievals) contains poisoning patterns before they enter the persistent memory, mapping a specific vector of third-party risk. |
| Map 4.2 | Internal risk controls for AI system components are identified. | AMG itself serves as a documented internal risk control for the memory subsystem of AI agents. |
| Map 5.1 | Likelihood and magnitude of impacts are identified. | AMG's detection statistics (threat types, frequency, confidence) provide empirical data for assessing likelihood and magnitude of memory poisoning impacts. |

### 1.3 MEASURE Function

The Measure function applies metrics and methodologies to assess AI risks. AMG provides quantitative measurement of memory security.

| Subcategory | Requirement | AMG Contribution |
|-------------|-------------|------------------|
| Measure 1.1 | Metrics for AI risks identified in Map are selected and implemented. | AMG provides concrete metrics: recall (92.5%), precision (100%), false positive rate (0% on the benchmark corpus), median scan latency (62 µs), threat type distribution, and temporal trends — all applicable to memory poisoning risk measurement. |
| Measure 2.4 | AI system functionality is monitored in production. | AMG's runtime scanning provides continuous production monitoring of memory operations, detecting drift or novel attack patterns as they emerge. |
| Measure 2.5 | The AI system is demonstrated to be valid and reliable. | AMG's benchmark suite with labeled attack corpus enables validation of detection reliability. The OpenSSF Best Practices badge (passing level) [5] documents software quality practices; the project's OpenSSF Scorecard [8] gives the current supply-chain posture. |
| Measure 2.6 | The AI system is evaluated for safety risks and demonstrated to be safe. | AMG directly evaluates safety by detecting patterns that could cause the agent to behave unsafely (e.g., ignoring safety instructions, leaking sensitive data). Scan latency metrics demonstrate real-time monitoring capability. |
| Measure 2.7 | AI system security and resilience are evaluated and documented. | AMG is the primary technical control for evaluating and documenting memory subsystem security. Detection logs provide evidence of security evaluation. |
| Measure 3.1 | Approaches to track existing and emergent AI risks are in place. | AMG's configurable policy engine allows new detection patterns to be added as emergent memory poisoning techniques are discovered, enabling continuous risk tracking. |
| Measure 4.1 | Measurement approaches are connected to deployment contexts. | AMG's framework-specific adapters (LangChain, CrewAI, AutoGen, Mem0) ensure measurements are contextually relevant to the specific deployment stack. |

### 1.4 MANAGE Function

The Manage function allocates resources and implements risk treatments. AMG provides active risk mitigation.

| Subcategory | Requirement | AMG Contribution |
|-------------|-------------|------------------|
| Manage 1.2 | Treatment of AI risks is prioritized based on impact and likelihood. | AMG's confidence scoring and threat categorization enable prioritized treatment — high-confidence threats are blocked immediately while lower-confidence detections can be queued for human review. |
| Manage 1.3 | Responses to high-priority risks are developed and documented. | AMG implements the "mitigate" response option by blocking poisoned memory writes. The "accept" option is supported via configurable thresholds. Detection logs document all risk responses. |
| Manage 2.2 | Mechanisms sustain the value of deployed AI systems. | By preventing memory corruption, AMG sustains the value and reliability of deployed AI agents over time — without memory protection, agent quality degrades as poisoned memories accumulate. |
| Manage 2.3 | Procedures respond to previously unknown risks. | AMG's policy update mechanism allows rapid deployment of new detection patterns when novel memory poisoning techniques are discovered. |
| Manage 2.4 | Mechanisms to disengage AI systems with inconsistent outcomes. | AMG's blocking mode can serve as a circuit breaker — if threat detection rates exceed a threshold, the system can halt memory operations pending human review. |
| Manage 3.1 | Third-party AI risks are monitored with applied controls. | AMG monitors all content entering the memory store, including outputs from third-party LLMs, tools, and retrieval systems, applying controls regardless of content origin. |
| Manage 4.1 | Post-deployment monitoring plans include incident response. | AMG's detection events integrate with incident response workflows. The MCP server interface enables automated alerting and response orchestration. |
| Manage 4.3 | Incidents are communicated and recovery processes documented. | AMG's structured detection output (threat type, confidence, content preview) provides the information needed for incident communication and post-incident analysis. |

---

## 2. EU AI Act (Regulation 2024/1689) Mapping

The EU AI Act establishes a risk-based regulatory framework for AI systems deployed in the European Union [6]. AI agents with persistent memory that make or influence decisions affecting individuals may qualify as high-risk AI systems under Article 6 and Annex III. The following mapping addresses the technical requirements applicable to high-risk AI systems.

### 2.1 Article 9: Risk Management System

Article 9 requires providers of high-risk AI systems to establish, implement, document, and maintain a risk management system throughout the AI system's lifecycle [6].

| Requirement | Article 9 Text (Summary) | AMG Contribution |
|-------------|--------------------------|------------------|
| Art. 9(2)(a) | Identification and analysis of known and reasonably foreseeable risks. | AMG's threat taxonomy identifies and categorizes the known risks of memory poisoning: injection, exfiltration, privilege escalation, persistence loops, tool abuse, and cross-task contamination. |
| Art. 9(2)(b) | Estimation and evaluation of risks when the system is used in accordance with its intended purpose and under conditions of reasonably foreseeable misuse. | AMG's benchmark suite provides empirical risk estimation. Measured recall of 92.5% under the tested conditions quantifies residual risk: on this corpus roughly 1 in 13 attack payloads was not detected. Residual risk outside the corpus is not quantified. |
| Art. 9(2)(c) | Evaluation of other risks based on post-market monitoring data. | AMG's production monitoring generates post-market data on emerging attack patterns, enabling continuous risk evaluation as the threat landscape evolves. |
| Art. 9(2)(d) | Adoption of appropriate and targeted risk management measures. | AMG is itself a targeted risk management measure — it specifically addresses memory poisoning without impacting legitimate agent functionality. |
| Art. 9(4) | Risk management measures shall give due consideration to the effects and possible interactions from combined application of requirements. | AMG's design considers interaction effects: it validates memory content without disrupting the agent's core functionality, maintaining both security and utility. |
| Art. 9(5) | Residual risks shall be communicated to the deployer. | AMG's detection confidence scores and false negative rate documentation communicate residual risk to deployers. |
| Art. 9(7) | Testing shall be suitable to identify relevant risks and be performed at appropriate points in the development process. | AMG provides a testing framework (benchmark suite, labeled dataset) suitable for validating memory security at development, pre-deployment, and post-deployment stages. |

### 2.2 Article 15: Accuracy, Robustness, and Cybersecurity

Article 15 requires high-risk AI systems to achieve appropriate levels of accuracy, robustness, and cybersecurity [6].

| Requirement | Article 15 Text (Summary) | AMG Contribution |
|-------------|---------------------------|------------------|
| Art. 15(1) | High-risk AI systems shall be designed and developed to achieve an appropriate level of accuracy, robustness, and cybersecurity. | AMG directly enhances cybersecurity by defending against memory poisoning — a class of adversarial attack that degrades both accuracy (corrupted context) and robustness (persistent compromise). |
| Art. 15(3) | High-risk AI systems shall be resilient against attempts by unauthorized third parties to alter their use, outputs, or performance by exploiting system vulnerabilities. | Memory poisoning is precisely this type of attack — unauthorized alteration of AI system behavior via exploited memory vulnerabilities. AMG provides resilience against these attempts. |
| Art. 15(3)(a) | Technical solutions shall be appropriate to the circumstances and risks, including measures to prevent and control attacks trying to manipulate the training dataset or pre-trained components. | While Art. 15(3)(a) focuses on training data, memory stores in AI agents function analogously — they are persistent data that shapes system behavior. AMG prevents manipulation of this behavioral data. |
| Art. 15(3)(b) | Technical solutions appropriate to prevent and control attacks trying to exploit system vulnerabilities to alter system behavior. | AMG prevents exploitation of the unvalidated memory write vulnerability (CWE-20) that exists in all major agent frameworks. |
| Art. 15(4) | High-risk AI systems shall be resilient against errors, faults, or inconsistencies that may occur within the system or its environment. | AMG provides resilience against inconsistencies introduced via poisoned memories — ensuring the agent's behavioral context remains consistent with its intended design. |

### 2.3 Article 9 and Article 17: Quality Management and Documentation

| Requirement | Summary | AMG Contribution |
|-------------|---------|------------------|
| Art. 9(8) | Risk management system shall be documented. | AMG's policy configuration, detection rules, and audit logs provide documented evidence of the risk management system for memory security. |
| Art. 17(1)(a) | Quality management system with documented strategy for regulatory compliance. | AMG's compliance mapping (this document), detection policies, and integration documentation support the quality management system. |
| Art. 17(1)(e) | Quality management includes risk management procedures. | AMG operationalizes risk management procedures for memory poisoning through configurable policies, automated detection, and structured incident reporting. |
| Art. 17(1)(h) | Post-market monitoring system. | AMG's continuous runtime scanning constitutes a post-market monitoring system for memory security, generating data for ongoing compliance demonstration. |

### 2.4 Article 13: Transparency and Information

| Requirement | Summary | AMG Contribution |
|-------------|---------|------------------|
| Art. 13(1) | High-risk AI systems shall be designed to ensure their operation is sufficiently transparent to enable deployers to interpret the system's output. | AMG's detection explanations (threat type, confidence, matched patterns) provide transparency about why a memory operation was blocked or flagged. |
| Art. 13(3)(b)(ii) | Instructions of use include the level of accuracy, robustness, and cybersecurity against which the system has been tested and validated. | AMG's published benchmark results (92.5% recall, 100% precision, per-category breakdown) provide accuracy and cybersecurity validation data. Deployers must note the corpus size (55 cases) when citing these figures under Art. 13(3)(b)(ii). |

---

## 3. Cross-Framework Summary

The following table provides a high-level summary of how AMG's core capabilities map across both frameworks.

| AMG Capability | NIST AI RMF Function | EU AI Act Article |
|----------------|---------------------|-------------------|
| Runtime memory scanning | Measure 2.4, 2.7 | Art. 15(1), 15(3) |
| Threat categorization | Map 1.1, Measure 1.1 | Art. 9(2)(a) |
| Confidence scoring | Measure 2.6, Manage 1.2 | Art. 9(5), 13(3) |
| Policy engine (configurable rules) | Govern 1.2, 1.5 | Art. 9(2)(d), 17(1)(e) |
| Blocking mode (active mitigation) | Manage 1.3, 2.4 | Art. 15(3), 15(3)(b) |
| Detection audit logs | Govern 4.3, Manage 4.3 | Art. 9(8), 17(1)(h) |
| Benchmark dataset | Map 2.3, Measure 2.5 | Art. 9(7), 13(3)(b)(ii) |
| Framework adapters (LangChain, etc.) | Measure 4.1 | Art. 9(4) |
| Observability integrations | Govern 1.5, Manage 4.1 | Art. 17(1)(h) |
| MCP server interface | Manage 2.3, 4.1 | Art. 15(4) |

---

## 4. Implementation Guidance

Organizations seeking to use AMG for regulatory compliance should consider the following implementation approach:

**For NIST AI RMF alignment:**

1. Document AMG deployment in the organization's AI system inventory (Govern 1.6).
2. Include memory poisoning in the risk assessment for all AI agents with persistent memory (Map 1.1).
3. Configure AMG policies to reflect organizational risk tolerance (Govern 1.3, Manage 1.2).
4. Integrate AMG detection metrics into existing monitoring dashboards (Measure 2.4).
5. Establish incident response procedures for AMG threat detections (Manage 4.1).

**For EU AI Act compliance:**

1. Include AMG in the technical documentation for high-risk AI systems (Art. 11).
2. Reference AMG's detection rates in accuracy and cybersecurity validation reports (Art. 15).
3. Configure AMG's audit logging to support the post-market monitoring system (Art. 72).
4. Document AMG's threat taxonomy in the risk management system documentation (Art. 9).
5. Include AMG detection explanations in deployer-facing transparency documentation (Art. 13).

---

## References

[1]: https://owasp.org/www-project-top-10-for-large-language-model-applications/ "OWASP Top 10 for Agentic Applications"
[2]: https://atlas.mitre.org/techniques/AML.T0080.000 "MITRE ATLAS: Poisoning — Memory"
[3]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework"
[4]: https://huggingface.co/datasets/vgudur/memory-poisoning-attack-corpus "Memory Poisoning Attack Corpus (HuggingFace)"
[5]: https://www.bestpractices.dev/projects/12908 "OpenSSF Best Practices Badge — Agent Memory Guard"
[6]: https://eur-lex.europa.eu/eli/reg/2024/1689/oj "Regulation (EU) 2024/1689 — Artificial Intelligence Act"
[7]: https://github.com/OWASP/www-project-agent-memory-guard/blob/main/benchmarks/results/benchmark_report.md "AMG Security Benchmark Report"
[8]: https://scorecard.dev/viewer/?uri=github.com/OWASP/www-project-agent-memory-guard "OpenSSF Scorecard - Agent Memory Guard"
