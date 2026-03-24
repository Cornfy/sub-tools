# 🚀 SUB-TOOL

A high-performance, **native Go** subscription converter for **Sing-box**. 

Stop relying on heavy JavaScript engines. **SUB-TOOL** brings the robustness of native Go and the precision of Sub-Store's parsing logic into a single, zero-dependency binary.

## 🌟 Key Features

- **Industrial-Grade Parsing**: Native implementation of complex protocol mapping (VLESS/Reality, VMess JSON/Query, Trojan, Shadowsocks SIP002, Hysteria 1/2).
- **Zero Runtime Dependencies**: No Node.js or JS engine required. A single static binary for Linux, Windows, macOS, and Android.
- **Diff-Friendly JSON**: Powered by `orderedmap`, it **strictly preserves the field order** of your `template.json` (e.g., Log -> DNS -> Outbounds).
- **Multi-Source Collection**: Aggregate nodes from multiple subscription URLs into a single configuration.
- **Smart Logic**:
    - **Regex-Based Grouping**: Categorize nodes into country-based `urltest` groups using flexible Regex.
    - **Keyword Filtering**: Clean up your node list by filtering out "Expired" or "Traffic" notices.
    - **Robust Base64**: Handles non-standard padding and URL-safe Base64 variants common in the wild.
- **Advanced Injection System**:
    - `<all-proxies>`: Expands to all filtered physical node tags.
    - `<all-region-groups>`: Expands to all generated region group tags.
    - `<dynamic-region-groups>`: Injects actual `urltest` group objects with relative order preserved.

## 🚀 Quick Start

### 1. Build
```bash
# Initialize and fetch dependencies
go mod tidy

# Build local version
make help
```

### 2. Usage

**SUB-TOOL** supports multiple operation modes:

```bash
# Generate full Sing-box config to stdout (using template.json)
./sub-tool -url "http://example.com/sub" -config-gen config.json

# Aggregate multiple sources into a specific file
./sub-tool -url "url1" -url "url2" -template my_tmpl.json -config-gen my_config.json

# Export ONLY a clean nodes list in JSON format
./sub-tool -url "http://example.com/sub" -node-gen nodes.json

# Check version
./sub-tool -v
```

## 🛠️ Configuration (template.json)

The `_extra` block controls the magic. It is automatically stripped from the final output:

```json
{
  "_extra": {
    "sub_url": "Optional default URL",
    "filter_keywords": "Reset|Remaining|Expired|Traffic",
    "regions": [
      ["Hong Kong|HK|🇭🇰", "🇭🇰 Hong Kong"],
      ["United States|US|🇺🇸", "🇺🇸 United States"]
    ]
  },
  "log": { "level": "info" },
  "outbounds": [
    {
      "type": "selector",
      "tag": "⚙️ Proxy",
      "outbounds": ["🎯 Direct", "<all-region-groups>", "<all-proxies>"]
    },
    "<dynamic-region-groups>",
    { "type": "direct", "tag": "🎯 Direct" }
  ]
}
```

## 📊 CLI Reference

| Flag | Description |
| :--- | :--- |
| `-url` | Subscription source URL. Can be specified multiple times. |
| `-template` | Path to your Sing-box template JSON. |
| `-config-gen` | Target path for the full configuration (`-` for stdout). |
| `-node-gen` | Target path for the raw nodes list JSON. |
| `-v`, `-version`| Show current version and build info. |

## 🛡️ Architecture

- **`main.go`**: Handles CLI, templates, and injection logic.
- **`converter/`**: The core protocol parsing engine.
    - `ParseNode`: The entry point for URI to Struct conversion.
    - `parseTransport/parseTLS`: Dedicated handlers for Reality, WS, gRPC, etc.

## ⚖️ License

MIT License. Feel free to use and contribute.
