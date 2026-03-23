package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// version 将在编译时通过链接器（linker）进行设置。
// 它的默认值 "development" 会在直接使用 `go run` 时显示。
var version = "development"

// --- 核心结构体定义 ---

type ExtraConfig struct {
	SubURL         string     `json:"sub_url"`
	FilterKeywords string     `json:"filter_keywords"`
	Regions        [][]string `json:"regions"`
}

type SingBoxConfig struct {
	Extra        *ExtraConfig    `json:"_extra,omitempty"`
	Log          json.RawMessage `json:"log,omitempty"`
	Experimental json.RawMessage `json:"experimental,omitempty"`
	DNS          json.RawMessage `json:"dns,omitempty"`
	Endpoints    json.RawMessage `json:"endpoints,omitempty"`
	Inbounds     json.RawMessage `json:"inbounds,omitempty"`
	Outbounds    []interface{}   `json:"outbounds,omitempty"`
	Route        json.RawMessage `json:"route,omitempty"`
}

type SingBoxOutbound struct {
	Type                      string           `json:"type"`
	Tag                       string           `json:"tag"`
	Server                    string           `json:"server,omitempty"`
	ServerPort                int              `json:"server_port,omitempty"`
	Method                    string           `json:"method,omitempty"`
	Password                  string           `json:"password,omitempty"`
	UUID                      string           `json:"uuid,omitempty"`
	Security                  string           `json:"security,omitempty"`
	TLS                       *TLSConfig       `json:"tls,omitempty"`
	Transport                 *TransportConfig `json:"transport,omitempty"`
	URL                       string           `json:"url,omitempty"`
	Interval                  string           `json:"interval,omitempty"`
	Tolerance                 int              `json:"tolerance,omitempty"`
	InterruptExistConnections bool             `json:"interrupt_exist_connections,omitempty"`
	Outbounds                 []string         `json:"outbounds,omitempty"`
}

type TLSConfig struct {
	Enabled    bool        `json:"enabled"`
	ServerName string      `json:"server_name,omitempty"`
	Insecure   bool        `json:"insecure"`
	UTLS       *UTLSConfig `json:"utls,omitempty"`
}
type UTLSConfig struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}
type TransportConfig struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}
type VMessJSON struct {
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	Id   string      `json:"id"`
	Net  string      `json:"net"`
	Path string      `json:"path"`
	Tls  string      `json:"tls"`
	Sni  string      `json:"sni"`
	Ps   string      `json:"ps"`
}

func main() {
	// 1. 定义并解析参数
	showVersion := flag.Bool("version", false, "显示版本号")
	flag.BoolVar(showVersion, "v", false, "显示版本号 (简写)")
	subURL := flag.String("url", "", "订阅链接 (若不提供则尝试读取模板中的 sub_url)")
	templatePath := flag.String("template", "template.json", "模板文件路径")
	outputPath := flag.String("output", "config.json", "输出文件路径")

	// 自定义帮助信息 (Flag Usage)
	flag.Usage = func() {
		// ANSI 颜色代码
		bold := "\033[1m"
		cyan := "\033[36m"
		yellow := "\033[33m"
		reset := "\033[0m"

		fmt.Fprintf(os.Stderr, "%s%sSUB-TOOL - Sing-box 订阅转换工具 (%s)%s\n\n", bold, cyan, version, reset)
		
		fmt.Fprintf(os.Stderr, "%s用法:%s\n  %s [参数]\n\n", yellow, reset, os.Args[0])
		
		fmt.Fprintf(os.Stderr, "%s参数列表:%s\n", yellow, reset)
		flag.VisitAll(func(f *flag.Flag) {
			// 将简写和全称合并显示（如果有的话）
			name := "-" + f.Name
			fmt.Fprintf(os.Stderr, "  %s%-15s%s %s (默认值: %q)\n", cyan, name, reset, f.Usage, f.DefValue)
		})

		fmt.Fprintf(os.Stderr, "\n%s模板占位符说明:%s\n", yellow, reset)
		fmt.Fprintf(os.Stderr, "  %s%-22s%s 展开为所有物理节点标签\n", cyan, "<all-proxies>", reset)
		fmt.Fprintf(os.Stderr, "  %s%-22s%s 展开为所有地区分组标签\n", cyan, "<all-region-groups>", reset)
		fmt.Fprintf(os.Stderr, "  %s%-22s%s 插入动态生成的地区 urltest 组\n", cyan, "<dynamic-region-groups>", reset)

		fmt.Fprintf(os.Stderr, "\n%s示例:%s\n", yellow, reset)
		fmt.Fprintf(os.Stderr, "  从模板获取 URL:   %s%s -template template.json%s\n", cyan, os.Args[0], reset)
		fmt.Fprintf(os.Stderr, "  手动指定订阅:     %s%s -url \"http://...\" -output config.json%s\n", cyan, os.Args[0], reset)
		fmt.Fprintf(os.Stderr, "  查看工具版本:     %s%s -v%s\n\n", cyan, os.Args[0], reset)
	}

	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "错误: 发现了非法参数: %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("Sub-Tool Version: %s\n", version)
		return
	}

	if _, err := os.Stat(*templatePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "错误: 模板文件 %q 不存在。\n", *templatePath)
		os.Exit(1)
	}

	// 2. 读取并解析模板
	tmplData, _ := os.ReadFile(*templatePath)
	var config SingBoxConfig
	if err := json.Unmarshal(tmplData, &config); err != nil {
		fmt.Printf("解析模板失败: %v\n", err)
		return
	}

	// 3. 确定并获取节点
	finalURL := *subURL
	if finalURL == "" && config.Extra != nil {
		finalURL = config.Extra.SubURL
	}
	if finalURL == "" {
		fmt.Println("错误: 未提供订阅链接。")
		return
	}
	rawNodes := fetchAndParseNodes(finalURL)

	// 4. 确定保底 Tag
	defaultTag := "direct"
	if len(config.Outbounds) > 0 {
		if first, ok := config.Outbounds[0].(map[string]interface{}); ok {
			if t, ok := first["tag"].(string); ok {
				defaultTag = t
			}
		}
	}

	// 5. 过滤物理节点并生成 allProxyTags
	var nodes []SingBoxOutbound
	if config.Extra != nil && config.Extra.FilterKeywords != "" {
		filterReg := regexp.MustCompile("(?i)" + config.Extra.FilterKeywords)
		for _, n := range rawNodes {
			if !filterReg.MatchString(n.Tag) {
				nodes = append(nodes, n)
			}
		}
	} else {
		nodes = rawNodes
	}

	var allProxyTags []string
	for _, n := range nodes {
		allProxyTags = append(allProxyTags, n.Tag)
	}
	if len(allProxyTags) == 0 {
		allProxyTags = []string{defaultTag}
	}

	// 6. 生成地区组 (regionGroups)
	var regionGroups []SingBoxOutbound
	var allRegionGroupTags []string
	if config.Extra != nil && len(config.Extra.Regions) > 0 {
		for _, conf := range config.Extra.Regions {
			if len(conf) < 2 { continue }
			reg := regexp.MustCompile("(?i)" + conf[0])
			var matchedTags []string
			for _, tag := range allProxyTags {
				if tag != defaultTag && reg.MatchString(tag) {
					matchedTags = append(matchedTags, tag)
				}
			}
			if len(matchedTags) == 0 { continue }

			tag := conf[1]
			regionGroups = append(regionGroups, SingBoxOutbound{
				Type:                      "urltest",
				Tag:                       tag,
				URL:                       "https://www.gstatic.com/generate_204",
				Interval:                  "3m",
				Tolerance:                 150,
				InterruptExistConnections: true,
				Outbounds:                 matchedTags,
			})
			allRegionGroupTags = append(allRegionGroupTags, tag)
		}
	}
	if len(allRegionGroupTags) == 0 {
		allRegionGroupTags = []string{defaultTag}
	}

	// 7. 替换占位符并统一顺序
	var finalOutbounds []interface{}
	for _, out := range config.Outbounds {
		// 处理字符串占位符
		if str, ok := out.(string); ok && str == "<dynamic-region-groups>" {
			for _, rg := range regionGroups {
				finalOutbounds = append(finalOutbounds, rg)
			}
			continue
		}

		// 处理对象（Selector/URLTest）
		if objMap, ok := out.(map[string]interface{}); ok {
			// 利用 Marshal/Unmarshal 固定顺序
			objBytes, _ := json.Marshal(objMap)
			var node SingBoxOutbound
			json.Unmarshal(objBytes, &node)

			if len(node.Outbounds) > 0 {
				var newSubOuts []string
				for _, so := range node.Outbounds {
					switch so {
					case "<all-proxies>":
						newSubOuts = append(newSubOuts, allProxyTags...)
					case "<all-region-groups>":
						newSubOuts = append(newSubOuts, allRegionGroupTags...)
					default:
						newSubOuts = append(newSubOuts, so)
					}
				}
				node.Outbounds = newSubOuts
			}
			finalOutbounds = append(finalOutbounds, node)
		}
	}

	// 8. 追加物理节点
	for _, n := range nodes {
		finalOutbounds = append(finalOutbounds, n)
	}

	config.Outbounds = finalOutbounds
	config.Extra = nil

	// 9. 输出
	finalJSON, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(*outputPath, finalJSON, 0644)
	fmt.Printf("[+] 转换完成！节点: %d, 地区组: %d, 保底: %s\n", len(nodes), len(regionGroups), defaultTag)
}

// --- 解析逻辑部分 ---

func fetchAndParseNodes(subURL string) []SingBoxOutbound {
	resp, err := http.Get(subURL)
	if err != nil { return nil }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := decodeSub(string(body))
	lines := strings.Split(content, "\n")
	var outbounds []SingBoxOutbound
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" { continue }
		var node *SingBoxOutbound
		if strings.HasPrefix(line, "trojan://") {
			node = parseStandard(line, "trojan")
		} else if strings.HasPrefix(line, "vmess://") {
			node = parseVMess(line)
		} else if strings.HasPrefix(line, "vless://") {
			node = parseStandard(line, "vless")
		} else if strings.HasPrefix(line, "ss://") {
			node = parseSS(line)
		}
		if node != nil { outbounds = append(outbounds, *node) }
	}
	return outbounds
}

func parseStandard(uri, protocolType string) *SingBoxOutbound {
	u, err := url.Parse(uri)
	if err != nil { return nil }
	port, _ := strconv.Atoi(u.Port())
	tag, _ := url.QueryUnescape(u.Fragment)
	node := &SingBoxOutbound{
		Tag: tag, Type: protocolType, Server: u.Hostname(), ServerPort: port,
	}
	if protocolType == "trojan" {
		node.Password = u.User.Username()
	} else {
		node.UUID = u.User.Username()
	}
	sni := u.Query().Get("sni")
	if sni == "" { sni = u.Hostname() }
	node.TLS = &TLSConfig{
		Enabled: true, ServerName: sni, Insecure: false,
		UTLS: &UTLSConfig{Enabled: true, Fingerprint: "chrome"},
	}
	return node
}

func parseVMess(uri string) *SingBoxOutbound {
	data := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil { return nil }
	var v VMessJSON
	if err := json.Unmarshal(decoded, &v); err != nil { return nil }
	var port int
	switch p := v.Port.(type) {
	case float64: port = int(p)
	case string: port, _ = strconv.Atoi(p)
	}
	node := &SingBoxOutbound{
		Tag: v.Ps, Type: "vmess", Server: v.Add, ServerPort: port, UUID: v.Id, Security: "auto",
	}
	if v.Tls == "tls" {
		sni := v.Sni
		if sni == "" { sni = v.Add }
		node.TLS = &TLSConfig{
			Enabled: true, ServerName: sni, Insecure: false,
			UTLS: &UTLSConfig{Enabled: true, Fingerprint: "chrome"},
		}
	}
	if v.Net != "" && v.Net != "tcp" {
		node.Transport = &TransportConfig{Type: v.Net, Path: v.Path}
	}
	return node
}

func parseSS(uri string) *SingBoxOutbound {
	u, _ := url.Parse(uri)
	tag, _ := url.QueryUnescape(u.Fragment)
	port, _ := strconv.Atoi(u.Port())
	userInfo := u.User.String()
	if dec, err := base64.RawURLEncoding.DecodeString(userInfo); err == nil {
		userInfo = string(dec)
	}
	node := &SingBoxOutbound{
		Tag: tag, Type: "shadowsocks", Server: u.Hostname(), ServerPort: port, Method: "aes-256-gcm",
	}
	if strings.Contains(userInfo, ":") {
		parts := strings.SplitN(userInfo, ":", 2)
		node.Method = parts[0]
		node.Password = parts[1]
	} else {
		node.Password = userInfo
	}
	return node
}

func decodeSub(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw)%4 != 0 { raw += strings.Repeat("=", 4-len(raw)%4) }
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(raw)
		if err != nil { return raw }
	}
	return string(decoded)
}
