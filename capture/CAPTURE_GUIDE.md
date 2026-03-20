# HAR Capture Guide

This guide explains how to capture HTTP Archive (HAR) files from AI chat platforms for analysis with the AI Transparency Suite.

## What is a HAR File?

A HAR (HTTP Archive) file is a JSON-formatted log of all HTTP transactions between your browser and web servers. It records every request and response — URLs, headers, cookies, payloads, and timing. All modern browsers can export HAR files through their Developer Tools.

## Requirements

- **Browser**: Google Chrome or Microsoft Edge (Chromium-based) recommended
- **DevTools access**: Must be able to open Developer Tools (F12)
- **Storage**: HAR files can be 5–100+ MB depending on session length

## Security Warning

**HAR files contain sensitive data including:**
- Session tokens and authentication cookies
- API keys embedded in requests
- Potentially your email, name, and other PII in API responses
- Full content of your conversations with AI platforms

**NEVER share raw HAR files publicly.** Always sanitize them first using the ATS tools, or manually remove sensitive headers and cookies before sharing.

## Step-by-Step Capture

### 1. Open Developer Tools

- **Chrome/Edge**: Press `F12` or `Ctrl+Shift+I` (Windows/Linux) / `Cmd+Option+I` (Mac)
- Navigate to the **Network** tab

### 2. Configure Network Panel

- Check **"Preserve log"** (prevents clearing on page navigation)
- Ensure **"Disable cache"** is checked for accurate results
- Set the filter to **"All"** to capture everything (you can also use "Fetch/XHR" for API calls only, but "All" gives complete picture)

### 3. Navigate to the Platform

Go to the AI chat platform you want to analyze:

| Platform | URL |
|----------|-----|
| Claude | https://claude.ai |
| ChatGPT | https://chatgpt.com |
| Grok | https://grok.com |
| DeepSeek | https://chat.deepseek.com |
| Gemini | https://gemini.google.com |

### 4. Use the Platform Normally

- Start a new conversation
- Send at least 2–3 messages
- Wait for complete responses
- Optionally: navigate between conversations, change settings, etc.
- The longer the session, the more telemetry you'll capture

### 5. Export the HAR File

- Right-click anywhere in the Network panel's request list
- Select **"Save all as HAR with content"** (Chrome) or **"Export HAR..."** (Edge)
- Save to a location you'll remember
- **Do NOT save to a cloud-synced folder** (the file contains session tokens)

## Capturing Incognito/Private Mode Sessions

To compare normal vs. private mode data collection:

### Normal Mode Capture
1. Follow steps 1–5 above in a regular browser window
2. Save as `platform_normal.har`

### Incognito/Private Mode Capture
1. Open an Incognito/InPrivate window (`Ctrl+Shift+N` in Chrome)
2. Open DevTools in the incognito window (F12)
3. Follow steps 2–5 above
4. Log in to the platform if required
5. Perform similar actions as your normal session
6. Save as `platform_incognito.har`

You can then compare both files using `analyze/har_incognito_auditor.py`.

## Platform-Specific Notes

### Claude (claude.ai)
- Uses streaming responses (EventSource/SSE) — these appear as long-running requests
- Look for requests to `api.segment.io` and `api2.amplitude.com` for third-party analytics
- Settings and organization API calls may reveal additional data collection

### ChatGPT (chatgpt.com)
- Heavy use of StatsIg for experiment infrastructure
- Look for `featuregates.org` and `statsig` requests
- Conversation list loads trigger additional telemetry
- May use WebSocket connections for real-time features

### Grok (grok.com)
- Watch for "thinking" token timestamps in API responses
- Streaming responses via SSE
- Check for analytics endpoints during idle periods

### DeepSeek (chat.deepseek.com)
- Monitor for keystroke-level event collection
- Check `postData` for granular interaction tracking
- Note the server locations in response headers

### Gemini (gemini.google.com)
- Uses Google's RPC/Protobuf infrastructure — requests may appear as batch RPC calls
- Endpoint paths use encoded format (e.g., `$rpc/google.internal.foo`)
- Response bodies may be in binary protobuf format (less readable)
- Integrates with Google's broader analytics ecosystem

## Validate Your Capture

Before running analysis, validate your HAR file:

```bash
python capture/har_validator.py your_capture.har
```

This checks:
- Valid JSON structure
- HAR format compliance
- Entry count and domain summary
- Warnings for sensitive data (tokens, cookies)

## Tips for Better Captures

1. **Start fresh**: Clear the Network panel before navigating to the platform
2. **Be thorough**: Interact with multiple features (chat, settings, history, file upload)
3. **Wait for idle**: After your last action, wait 30–60 seconds to capture delayed telemetry
4. **Capture both modes**: Normal and incognito captures together provide the strongest evidence
5. **Note the date**: Platform behavior changes over time; record when you captured
6. **Multiple sessions**: Capture on different days to confirm patterns are consistent
