# 🚀 SUB-TOOL

A high-performance, **native Go** subscription converter for **Sing-box**. 

Convert common proxy share links into sing-box outbounds, or inject them into a configuration template. No JavaScript runtime is needed.

## 🌟 Key Features

- **Share-Link Parsing**: VLESS/Reality, VMess JSON/Query, Trojan, Shadowsocks SIP002/legacy, Hysteria2, TUIC v5 and AnyTLS. See the support limits below.
- **Zero Runtime Dependencies**: No Node.js or JS engine required. A single static binary for Linux, Windows, macOS, and Android.
- **Diff-Friendly JSON**: Powered by `orderedmap`, it **strictly preserves the field order** of your `template.json` (e.g., Log -> DNS -> Outbounds).
- **Multi-Source Collection**: Aggregate nodes from multiple subscription URLs into a single configuration directly via template or CLI.
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

# Build with version info (v0.3.0 for example)
go build -ldflags "-X main.version=v0.3.0" -o sub-tool .

# Build using Makefile
make build

# Get help information for the Makefile
make help
```

### 2. Usage

**SUB-TOOL** supports multiple operation modes:

```bash
# Generate full Sing-box config (using template.json)
./sub-tool -url "http://example.com/sub" -config-gen config.json

# Aggregate multiple sources into a specific file
./sub-tool -url "url1" -url "url2" -template my_tmpl.json -config-gen my_config.json

# Export ONLY a clean nodes list in JSON format
./sub-tool -url "http://example.com/sub" -node-gen nodes.json

# Check version
./sub-tool -v
```

## 🛠️ Configuration (template.json)

The `_extra` block controls the magic. It is automatically stripped from the final output. 

> **⚠️ Breaking Changes in v0.3.0:**
> 1. `sub_url` (String) has been replaced by `sub_urls` (List of [Label, URL]).
> 2. `regions` format is now strictly `["Group Label", "Regex Pattern"]`.

```json
{
  "_extra": {
    "sub_urls": [
      ["Main Source", "https://example.com/sub1"],
      ["Backup Source", "https://example.com/sub2"]
    ],
    "filter_keywords": "Reset|Remaining|Expired|Traffic",
    "regions": [
      ["🇭🇰 Hong Kong", "Hong Kong|HK|🇭🇰"],
      ["🇺🇸 United States", "United States|US|🇺🇸"]
    ]
  },
  "outbounds": [
    { "type": "direct", "tag": "🎯 Direct" },
    {
      "type": "selector",
      "tag": "⚙️ Proxy",
      "outbounds": ["🎯 Direct", "<all-region-groups>", "<all-proxies>"]
    },
    "<dynamic-region-groups>"
  ]
}
```

## Supported formats and limits

Subscriptions may contain newline-separated share links or a Base64/Base64URL
wrapper. Missing padding, wrapped Base64 lines and a UTF-8 BOM are accepted.
Clash YAML, complete sing-box JSON, SSR and Hysteria v1 share links are not
supported. Hysteria v1 is explicitly rejected rather than emitted as an incomplete
configuration.

| Protocol | Supported share-link fields |
| :--- | :--- |
| VLESS | UUID, TLS/Reality, uTLS, `flow=xtls-rprx-vision`, packet encoding and V2Ray transports |
| VMess | Base64 JSON, direct or Base64-wrapped query links, cipher/alter ID, TLS/uTLS, packet encoding and V2Ray transports |
| Trojan | URL-decoded password, TLS/uTLS and V2Ray transports |
| Shadowsocks | SIP002 plain/Base64 user info, legacy whole-authority Base64, SS2022 plain keys, `obfs-local`/`v2ray-plugin` |
| Hysteria2 / hy2 | URL-decoded password/userpass, implicit TLS, port hopping, Salamander and optional bandwidth overrides |
| TUIC v5 | UUID/password, implicit TLS, congestion control, UDP relay settings, 0-RTT and heartbeat |
| AnyTLS | URL-decoded password, implicit TLS and idle session settings (sing-box 1.12+) |

Supported V2Ray transports are TCP (no transport object), WebSocket, HTTP
(`h2` is normalized to `http`), HTTPUpgrade, gRPC `gun` and plain V2Ray QUIC.
VMess JSON uses the same transport mapping as query links. HTTPUpgrade emits a
string `host`; HTTP emits a host array; gRPC emits `service_name` rather than HTTP
fields. TCP HTTP camouflage, gRPC `multi`, encrypted V2Ray QUIC and unsupported
transport types are rejected. New transport families are outside this support
scope.

VLESS/VMess accept `packetEncoding` or `packet_encoding`: `xudp`, `packetaddr`
or an explicit empty value. The default remains `xudp`. Empty values survive JSON
serialization, allowing UDP packet encoding to be disabled explicitly.

Passwords and node names are URL-decoded exactly once. JSON is serialized without
text replacement, preserving literal escapes and bracketed credential values.
Missing/invalid server
addresses, ports, UUIDs, required credentials, known boolean options and duplicate
query parameters are rejected. Successful conversion checks structure, not
connectivity or whether the server accepts the credentials.

### TLS and Reality

TLS supports `sni`/`serverName`/`server_name`/`peer`, `alpn`,
`fp`/`fingerprint`/`browser`, and insecure settings using `allowInsecure`, `insecure`,
`allow_insecure` or `skip-cert-verify`. Insecure verification is never enabled by
default. Values such as `1` and `true` are recognized.

VLESS Reality links enable `tls.reality` and uTLS (default fingerprint `chrome`).
A compatible sing-box build needs `with_utls`. Supported aliases, in first
nonempty order:

| Field | Parameters |
| :--- | :--- |
| Public key | `pbk`, `publicKey`, `public_key` |
| Short ID | `sid`, `shortId`, `short_id` |

The public key must decode to 32 bytes using unpadded Base64URL. The Short ID
must contain an even number of hexadecimal digits, at most 16; it may be empty.
`pinSHA256` and `ech` are explicitly rejected because they cannot currently be
faithfully mapped by this converter.

### Protocol-specific options

- **Shadowsocks:** `plugin` is split into `plugin` and `plugin_opts` without
  discarding plugin options. `simple-obfs` is normalized to `obfs-local`;
  unsupported plugin names and cipher names are rejected. See
  [SIP002](https://shadowsocks.org/doc/sip002.html) and
  [sing-box plugin support](https://sing-box.sagernet.org/configuration/outbound/shadowsocks/).
- **Hysteria2:** omitted ports default to 443. Multi-port authority syntax such as
  `HOST:443,5000-5010`, or query aliases `mport`/`ports`/`server_ports`, produce
  `server_ports` with sing-box range syntax. `hop_interval`/`hopInterval` accepts
  positive durations or an integer number of seconds, and requires a port list.
  Salamander requires `obfs=salamander` and `obfs-password`; unsupported obfuscation
  types are rejected. Optional bandwidth aliases are `upmbps`/`up_mbps` and
  `downmbps`/`down_mbps`. See the
  [Hysteria2 URI specification](https://v2.hysteria.network/docs/developers/URI-Scheme/).
- **TUIC:** `congestion_control`, `udp_relay_mode`, `udp_over_stream`,
  `zero_rtt_handshake` and `heartbeat`. Unsupported modes and conflicting UDP
  settings are rejected. UUID and password are both required.
- **AnyTLS:** `idle_session_check_interval`, `idle_session_timeout` and
  `min_idle_session`. Client metadata is not mapped.

Subscription downloads have a 30-second timeout and a 16 MiB body limit. HTTP
errors and truncated/empty responses are reported using messages that do not
expose the subscription URL. Skipped nodes are summarized using fixed categories
and counts; source labels elsewhere in the logs may still be private.

## Template resource downloads

The example template uses sing-box 1.14 HTTP clients: rule sets use
`RuleSet-HTTP-Client` without a detour, allowing startup downloads before node
latency tests complete. The dashboard retains `Default-HTTP-Client` through the
proxy selector. Do not set an empty direct outbound as an HTTP client detour.

## Tests

```bash
go test ./...
go vet ./...
```

Regression tests use synthetic credentials only. If `sing-box` is on PATH,
compatibility tests also validate generated outbounds with `sing-box check`.
Set `SING_BOX_BINARY` to choose another build; no live node connections are made.

## 📊 CLI Reference

| Flag | Description |
| :--- | :--- |
| `-url` | Subscription source URL. Can be specified multiple times to merge sources. |
| `-template` | Path to your Sing-box template JSON. |
| `-config-gen` | Target path for the full configuration (`-` for stdout). |
| `-node-gen` | Target path for the raw nodes list JSON. |
| `-v`, `-version`| Show current version and build info. |

## 🛡️ Architecture

- **`main.go`**: Handles CLI, templates, and injection logic.
- **`converter/`**: The core protocol parsing engine.
    - `ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound`: URI to outbound conversion.
    - Shared credential, TLS, transport and option validation for supported link formats.

## ⚖️ License

MIT License. Feel free to use and contribute.
