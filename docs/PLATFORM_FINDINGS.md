# Platform Findings Summary

This document summarizes publicly observable data collection patterns across AI chat platforms. All findings are based on passive HAR file analysis. No real user data is included.

## Claude (Anthropic) — claude.ai

- Telemetry integrations observed: Segment.io, Amplitude
- Analytics calls persist in incognito mode
- Multiple third-party domains contacted during standard chat sessions
- Some telemetry endpoints not referenced in published privacy policy

## ChatGPT (OpenAI) — chatgpt.com

- High ratio of telemetry-to-functional API calls observed
- StatsIg experiment infrastructure with feature gates and A/B test assignments
- Experiment configuration payloads contain detailed user segmentation
- Multiple observed analytics integrations not referenced in published privacy policy

## Grok (xAI) — grok.com

- Thinking token timestamps present in API responses
- Computation occurs during "thinking" phases with timing data observable in API responses
- Telemetry endpoints active during chat sessions

## DeepSeek — chat.deepseek.com

- Keystroke-level event collection observed in network traffic
- Data routed through servers with Chinese jurisdiction
- Encryption implementation details observable in traffic analysis
- Broad telemetry collection during standard usage

## Gemini (Google) — gemini.google.com

- RPC-based API architecture where endpoint purposes are not readily apparent
- Complex request/response structure makes analysis more difficult than other platforms
- Integration with broader Google analytics infrastructure
- Protobuf encoding reduces transparency of data payloads

---

*These findings reflect point-in-time observations. Platforms update their infrastructure regularly. Run ATS tools against your own captures for current results.*
