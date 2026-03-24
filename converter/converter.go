package converter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// SingBoxOutbound 定义了 sing-box 1.11+ 的全集字段
type SingBoxOutbound struct {
	Type           string           `json:"type"`
	Tag            string           `json:"tag"`
	Server         string           `json:"server,omitempty"`
	ServerPort     int              `json:"server_port,omitempty"`
	Method         string           `json:"method,omitempty"`
	Password       string           `json:"password,omitempty"`
	UUID           string           `json:"uuid,omitempty"`
	Security       string           `json:"security,omitempty"`
	AlterId        int              `json:"alter_id,omitempty"`
	Flow           string           `json:"flow,omitempty"`
	PacketEncoding string           `json:"packet_encoding,omitempty"`
	TLS            *TLSConfig       `json:"tls,omitempty"`
	Transport      *TransportConfig `json:"transport,omitempty"`
	Obfs           *Hy2ObfsConfig   `json:"obfs,omitempty"`
	UpMbps         int              `json:"up_mbps,omitempty"`
	DownMbps       int              `json:"down_mbps,omitempty"`
	AuthStr        string           `json:"auth_str,omitempty"`
	// 模板专用字段
	Outbounds []string    `json:"outbounds,omitempty"`
	URL       string      `json:"url,omitempty"`
	Interval  string      `json:"interval,omitempty"`
	Tolerance interface{} `json:"tolerance,omitempty"`
}

type TLSConfig struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name,omitempty"`
	Insecure   bool           `json:"insecure,omitempty"`
	Alpn       []string       `json:"alpn,omitempty"`
	UTLS       *UTLSConfig    `json:"utls,omitempty"`
	Reality    *RealityConfig `json:"reality,omitempty"`
}

type UTLSConfig struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RealityConfig struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key,omitempty"`
	ShortId   string `json:"short_id,omitempty"`
}

type TransportConfig struct {
	Type                string            `json:"type"`
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	ServiceName         string            `json:"service_name,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
	Host                []string          `json:"host,omitempty"`
}

type Hy2ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

type VMessRawJSON struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	ID   string      `json:"id"`
	Aid  interface{} `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	Sni  string      `json:"sni"`
	Ps   string      `json:"ps"`
}

func RobustBase64Decode(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "-", "+")
	raw = strings.ReplaceAll(raw, "_", "/")
	if len(raw)%4 != 0 {
		raw += strings.Repeat("=", 4-len(raw)%4)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	return string(decoded), err
}

func ToInt(v interface{}) int {
	switch val := v.(type) {
	case float64: return int(val)
	case string:
		i, _ := strconv.Atoi(val)
		return i
	case int: return val
	default: return 0
	}
}

func ParseNode(uri string) (*SingBoxOutbound, error) {
	if strings.HasPrefix(uri, "vmess://") {
		return parseVMess(uri)
	}
	protocols := []string{"vless", "trojan", "ss", "hysteria2", "hy2", "hysteria"}
	for _, p := range protocols {
		if strings.HasPrefix(uri, p+"://") {
			return parseStandardQueryStyle(p, uri)
		}
	}
	return nil, fmt.Errorf("unsupported protocol")
}

func parseTLS(protocol string, query url.Values) *TLSConfig {
	security := strings.ToLower(query.Get("security"))
	tlsParam := strings.ToLower(query.Get("tls"))
	isImplicit := protocol == "trojan" || protocol == "hysteria2" || protocol == "hy2" || protocol == "hysteria"
	
	if !(isImplicit || security == "tls" || security == "reality" || tlsParam == "1" || tlsParam == "true") {
		return nil
	}

	tls := &TLSConfig{Enabled: true, ServerName: query.Get("sni")}
	if tls.ServerName == "" { tls.ServerName = query.Get("peer") }
	if query.Get("allowInsecure") == "1" || query.Get("insecure") == "1" { tls.Insecure = true }
	if alpn := query.Get("alpn"); alpn != "" { tls.Alpn = strings.Split(alpn, ",") }
	
	fp := query.Get("fp")
	if fp == "" { fp = query.Get("browser") }
	if fp != "" {
		tls.UTLS = &UTLSConfig{Enabled: true, Fingerprint: fp}
	}

	if security == "reality" {
		tls.Reality = &RealityConfig{Enabled: true, PublicKey: query.Get("pbk"), ShortId: query.Get("sid")}
		if tls.UTLS == nil { tls.UTLS = &UTLSConfig{Enabled: true, Fingerprint: "chrome"} }
	}
	return tls
}

func parseTransport(query url.Values) *TransportConfig {
	netType := query.Get("net")
	if netType == "" { netType = query.Get("type") }
	if netType == "" || netType == "tcp" { return nil }

	trans := &TransportConfig{Type: netType}
	host := query.Get("host")

	switch netType {
	case "ws":
		trans.Path = query.Get("path")
		if trans.Path == "" { trans.Path = "/" }
		if host != "" { trans.Headers = map[string]string{"Host": host} }
		if ed := query.Get("ed"); ed != "" {
			trans.MaxEarlyData = ToInt(ed)
			trans.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		if query.Get("v2ray-http-upgrade") == "true" || query.Get("v2ray-http-upgrade") == "1" {
			trans.Type = "httpupgrade"
			if host != "" { trans.Host = []string{host} }
		}
	case "grpc":
		trans.ServiceName = query.Get("serviceName")
		if trans.ServiceName == "" { trans.ServiceName = query.Get("path") }
	case "httpupgrade", "http", "h2":
		trans.Path = query.Get("path")
		if host != "" { trans.Host = strings.Split(host, ",") }
	}
	return trans
}

func parseVMess(uri string) (*SingBoxOutbound, error) {
	decoded, err := RobustBase64Decode(strings.TrimPrefix(uri, "vmess://"))
	if err != nil { return nil, err }

	var v VMessRawJSON
	if json.Unmarshal([]byte(decoded), &v) == nil && v.Add != "" {
		out := &SingBoxOutbound{
			Type: "vmess", Tag: v.Ps, Server: v.Add, ServerPort: ToInt(v.Port),
			UUID: v.ID, Security: v.Scy, AlterId: ToInt(v.Aid), PacketEncoding: "xudp",
		}
		if out.Security == "" { out.Security = "auto" }
		if v.TLS == "tls" {
			out.TLS = &TLSConfig{Enabled: true, ServerName: v.Sni}
			if out.TLS.ServerName == "" { out.TLS.ServerName = v.Host }
		}
		if v.Net != "" && v.Net != "tcp" {
			out.Transport = &TransportConfig{Type: v.Net, Path: v.Path}
			if v.Host != "" && (v.Net == "ws" || v.Net == "httpupgrade") {
				out.Transport.Headers = map[string]string{"Host": v.Host}
			}
		}
		return out, nil
	}
	return parseStandardQueryStyle("vmess", decoded)
}

func parseStandardQueryStyle(protocol, uri string) (*SingBoxOutbound, error) {
	if !strings.Contains(uri, "://") { uri = protocol + "://" + uri }
	u, err := url.Parse(uri)
	if err != nil { return nil, err }

	query := u.Query()
	tag, _ := url.QueryUnescape(u.Fragment)
	if tag == "" { tag = u.Hostname() + ":" + u.Port() }

	out := &SingBoxOutbound{
		Type: protocol, Tag: tag, Server: u.Hostname(), ServerPort: ToInt(u.Port()),
	}

	userInfo := u.User.String()
	if protocol == "ss" && !strings.Contains(userInfo, ":") {
		if dec, err := RobustBase64Decode(userInfo); err == nil { userInfo = dec }
	}

	if strings.Contains(userInfo, ":") {
		parts := strings.SplitN(userInfo, ":", 2)
		if protocol == "ss" { out.Method, out.Password = parts[0], parts[1] } else if protocol == "trojan" { out.Password = parts[0] } else { out.UUID = parts[0] }
	} else {
		if protocol == "trojan" || protocol == "ss" { out.Password = userInfo } else { out.UUID = userInfo }
	}

	out.TLS = parseTLS(protocol, query)
	out.Transport = parseTransport(query)

	switch protocol {
	case "vless":
		out.Flow = query.Get("flow")
		out.PacketEncoding = "xudp"
	case "vmess":
		out.PacketEncoding = "xudp"
		if out.Security == "" { out.Security = "auto" }
	case "hysteria2", "hy2":
		out.Type = "hysteria2"
		out.Password = userInfo
		out.UpMbps = ToInt(query.Get("upmbps"))
		out.DownMbps = ToInt(query.Get("downmbps"))
		if ob := query.Get("obfs"); ob != "" && ob != "none" {
			out.Obfs = &Hy2ObfsConfig{Type: "salamander", Password: query.Get("obfs-password")}
		}
	}
	return out, nil
}
