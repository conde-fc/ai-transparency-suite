# Forensic Methodology

## Overview

The AI Transparency Suite uses a passive observation methodology to analyze what data AI chat platforms collect during normal usage. This document explains the approach, its limitations, and why the findings are independently reproducible.

## Capture Method: HAR Files

HAR (HTTP Archive) is a standardized JSON format that records all HTTP transactions between a browser and the servers it communicates with. Every modern browser with DevTools can export HAR files.

### What HAR Files Contain

- Every HTTP request URL, method, and headers
- Request bodies (including JSON payloads sent to APIs)
- Response headers and bodies
- Timing information
- Cookies sent and received

### How to Capture

1. Open browser DevTools (F12 or Ctrl+Shift+I)
2. Navigate to the **Network** tab
3. Ensure "Preserve log" is checked
4. Use the AI chat platform normally
5. Right-click in the Network panel → **Export HAR**

This is the same data your browser already processes. No interception, proxy, or modification is involved.

## Analysis Approach

### Passive Observation Only

ATS analyzes what platforms **voluntarily send to the browser** during normal operation. The tools:

- **Do not** intercept or modify network traffic
- **Do not** inject code into web pages
- **Do not** use browser extensions that alter requests
- **Do not** bypass encryption or security measures
- **Do not** access server-side systems

### Classification

Each HTTP request in a HAR file is classified based on observable characteristics:

1. **Domain** — Is it the platform's own domain or a third party?
2. **Path patterns** — Does the URL path indicate analytics, telemetry, or functional use?
3. **Payload content** — What data fields are present in request/response bodies?
4. **Known patterns** — Does the request match known analytics services (Segment, Amplitude, StatsIg)?

Classification rules are stored in `schemas/` JSON files and can be inspected, modified, and extended by anyone.

### Functional vs. Telemetry

- **Functional**: Requests that directly serve the user's intent (sending a message, receiving a response, loading the UI)
- **Telemetry**: Requests that collect data about the user or their behavior without directly serving the user's request (analytics pings, experiment assignments, tracking pixels)

### Reproducibility

Every finding produced by ATS can be independently verified:

1. Capture your own HAR file from the same platform
2. Run the same analysis tools
3. Compare results

The tools are deterministic — the same input produces the same output.

## Limitations

- HAR files capture browser-level traffic only; server-side processing is not visible
- HTTPS encryption means we see request/response content only because the browser decrypts it for DevTools
- Platforms may use additional data collection mechanisms not visible in HAR files (e.g., WebSocket frames may not be fully captured)
- Classification rules are based on known patterns and may not catch novel telemetry methods
- Results reflect a point-in-time snapshot; platforms update their infrastructure regularly

## Ethical Considerations

- Always sanitize HAR files before sharing (they contain session tokens and may contain PII)
- This toolkit is for personal research and consumer rights — not for attacking or disrupting services
- Findings should be reported responsibly and accurately
- Do not share raw HAR files publicly
