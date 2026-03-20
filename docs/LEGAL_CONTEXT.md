# Legal Context

This document provides an overview of the regulatory frameworks relevant to AI platform data collection transparency. **This is not legal advice.** Consult a qualified attorney for guidance specific to your situation.

## United States

### FTC Act — Section 5

The Federal Trade Commission Act prohibits "unfair or deceptive acts or practices in or affecting commerce." When a platform's privacy policy states it collects certain categories of data but actually collects significantly more, this may constitute a deceptive practice.

**Relevance to ATS findings:** If analysis reveals data collection that contradicts or exceeds a platform's published privacy disclosures, this evidence may support an FTC complaint.

- FTC Complaint Assistant: https://reportfraud.ftc.gov/
- FTC guidance on data privacy: https://www.ftc.gov/business-guidance/privacy-security

### CCPA / CPRA (California)

The California Consumer Privacy Act (as amended by CPRA) grants California residents:

- **Right to know** what personal information is collected (Cal. Civ. Code § 1798.100)
- **Right to delete** personal information (§ 1798.105)
- **Right to opt-out** of sale/sharing of personal information (§ 1798.120)
- **Right to non-discrimination** for exercising privacy rights (§ 1798.125)

The CPRA added specific provisions regarding **automated decision-making technology (ADMT)**, including profiling, which may apply to AI chat platform telemetry.

**Relevance to ATS findings:** If a platform collects data categories not disclosed in its CCPA-required privacy notice, consumers may have grounds for a complaint to the California Attorney General or California Privacy Protection Agency.

### State Privacy Laws

Multiple states have enacted comprehensive privacy laws with similar rights:

- Virginia Consumer Data Protection Act (VCDPA)
- Colorado Privacy Act (CPA)
- Connecticut Data Privacy Act (CTDPA)
- Utah Consumer Privacy Act (UCPA)
- Texas Data Privacy and Security Act (TDPSA)

Each provides some combination of access, deletion, and opt-out rights.

## European Union

### General Data Protection Regulation (GDPR)

The GDPR provides strong data subject rights for EU/EEA residents:

- **Article 13/14** — Right to be informed about data collection at the time it occurs
- **Article 15** — Right of access to personal data
- **Article 17** — Right to erasure ("right to be forgotten")
- **Article 20** — Right to data portability
- **Article 21** — Right to object to processing
- **Article 22** — Rights related to automated decision-making and profiling

**Relevance to ATS findings:** GDPR requires that data subjects be informed of all data processing at the time of collection. Undisclosed telemetry, third-party analytics integrations, or experiment infrastructure may violate Articles 13/14. Data subject access requests (DSARs) under Article 15 can be compared against ATS analysis to identify gaps between what a platform discloses and what it actually collects.

### Filing a Complaint

EU residents can file complaints with their national Data Protection Authority (DPA):
- List of DPAs: https://edpb.europa.eu/about-edpb/about-edpb/members_en

## How ATS Supports Consumer Rights

| ATS Tool | Regulatory Use |
|----------|---------------|
| `har_telemetry_counter` | Quantifies undisclosed data collection volume |
| `har_domain_inventory` | Identifies undisclosed third-party data recipients |
| `har_experiment_detector` | Documents undisclosed profiling/experimentation |
| `har_pii_scanner` | Identifies specific PII transmitted without consent |
| `har_incognito_auditor` | Proves tracking persists despite "private" mode claims |
| `har_field_classifier` | Catalogs all data fields for comparison against disclosures |
| `policy_field_mapper` | Directly maps collected data to policy gaps |
| `export_gap_analyzer` | Compares data exports against actual collection |

## Important Notes

- Capturing your own network traffic (HAR files) for personal analysis is generally lawful
- ATS performs passive analysis only — no interception, injection, or modification of traffic
- Always sanitize HAR files before sharing to protect your own credentials and PII
- Filing regulatory complaints should be based on documented, reproducible evidence
- Platforms may update their practices; findings are point-in-time snapshots
