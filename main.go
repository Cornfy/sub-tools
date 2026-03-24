package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"sub-tool/converter"

	"github.com/iancoleman/orderedmap"
)

var version = "development"

type urlSlice []string
func (s *urlSlice) String() string { return strings.Join(*s, ", ") }
func (s *urlSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type singleString struct {
	value string
	isSet bool
}
func (s *singleString) String() string { return s.value }
func (s *singleString) Set(v string) error {
	if s.isSet { return fmt.Errorf("只能指定一个模板文件") }
	s.value = v
	s.isSet = true
	return nil
}

type ExtraConfig struct {
	SubURL         string     `json:"sub_url"`
	FilterKeywords string     `json:"filter_keywords"`
	Regions        [][]string `json:"regions"`
}

func main() {
	var urls urlSlice
	flag.Var(&urls, "url", "订阅源 (可多次指定)")
	var tmpl singleString
	flag.Var(&tmpl, "template", "转换模板")
	nodeOut := flag.String("node-gen", "SKIP", "输出纯节点 JSON 路径")
	configOut := flag.String("config-gen", "SKIP", "输出完整配置路径")
	showVersion := flag.Bool("version", false, "显示版本号")
	flag.BoolVar(showVersion, "v", false, "显示版本号 (简写)")

	flag.Usage = func() {
		bold, cyan, yellow, reset := "\033[1m", "\033[36m", "\033[33m", "\033[0m"
		fmt.Fprintf(os.Stderr, "%s%s🚀 SUB-TOOL - Sing-box 订阅转换工具 (%s)%s\n\n", bold, cyan, version, reset)
		fmt.Fprintf(os.Stderr, "%s用法:%s\n  %s [参数]\n\n", yellow, reset, os.Args[0])
		fmt.Fprintf(os.Stderr, "%s参数列表:%s\n", yellow, reset)
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "  %s-%-15s%s %s\n", cyan, f.Name, reset, f.Usage)
		})
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("Sub-Tool Version: %s\n", version)
		return
	}

	hasNodeAction := isFlagPassed("node-gen")
	hasConfigAction := isFlagPassed("config-gen")
	if !hasNodeAction && !hasConfigAction {
		if len(urls) > 0 || tmpl.isSet {
			if tmpl.isSet { hasConfigAction = true; *configOut = "-" } else { hasNodeAction = true; *nodeOut = "-" }
			fmt.Fprintln(os.Stderr, "💡 提示: 未指定输出动作，默认开启 Stdout 输出模式")
		} else { flag.Usage(); return }
	}

	var oConf *orderedmap.OrderedMap
	var extra ExtraConfig
	effectiveTmpl := tmpl.value

	if hasConfigAction {
		if effectiveTmpl == "" {
			if _, err := os.Stat("template.json"); err == nil {
				effectiveTmpl = "template.json"
				fmt.Fprintln(os.Stderr, "⚠️  自动回退至 template.json")
			} else {
				fmt.Fprintln(os.Stderr, "❌ 错误: 生成配置必须提供模板文件。")
				os.Exit(1)
			}
		}
		oConf = loadTemplate(effectiveTmpl)
		extra = getExtra(oConf)
	} else if hasNodeAction {
		if _, err := os.Stat("template.json"); err == nil && effectiveTmpl == "" {
			fmt.Fprintln(os.Stderr, "ℹ️  已加载 template.json 中的过滤规则")
			extra = getExtra(loadTemplate("template.json"))
		}
	}

	var finalURLList []string
	if len(urls) > 0 { finalURLList = urls } else if extra.SubURL != "" { finalURLList = []string{extra.SubURL} }

	if len(finalURLList) == 0 {
		fmt.Fprintln(os.Stderr, "❌ 错误: 没有任何订阅源。")
		os.Exit(1)
	}

	allNodes := collectWithStats(finalURLList, extra)

	if len(allNodes) == 0 {
		fmt.Fprintln(os.Stderr, "❌ 错误: 未能在提供的源中找到任何有效节点，操作终止。")
		os.Exit(1)
	}

	if hasNodeAction {
		fmt.Fprintln(os.Stderr, "📝 正在生成节点列表...")
		data, _ := json.MarshalIndent(allNodes, "", "  ")
		writeToTarget(fixGoJsonStyle(string(data)), *nodeOut, "节点列表")
	}

	if hasConfigAction {
		fmt.Fprintln(os.Stderr, "⚙️  正在执行注入...")
		finalConf := injectToTemplate(oConf, extra, allNodes)
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		encoder.Encode(finalConf)
		writeToTarget(fixGoJsonStyle(buf.String()), *configOut, "完整配置")
	}
}

func collectWithStats(urls []string, extra ExtraConfig) []converter.SingBoxOutbound {
	results := []converter.SingBoxOutbound{}
	seen := make(map[string]bool)
	totalF, totalFilt, totalD := 0, 0, 0
	var filterReg *regexp.Regexp
	if extra.FilterKeywords != "" {
		filterReg = regexp.MustCompile("(?i)" + extra.FilterKeywords)
	}

	for i, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || u == "--" { continue }
		fmt.Fprintf(os.Stderr, "🌐 [%d/%d] 正在抓取: %s\n", i+1, len(urls), u)
		raw := fetchSubscription(u)
		if raw == "" {
			fmt.Fprintln(os.Stderr, "   ⚠️  抓取失败：内容为空")
			continue
		}
		decoded, err := converter.RobustBase64Decode(raw)
		if err != nil { decoded = raw }

		count := 0
		for _, line := range strings.Split(decoded, "\n") {
			node, err := converter.ParseNode(strings.TrimSpace(line))
			if err == nil && node != nil {
				totalF++
				if filterReg != nil && filterReg.MatchString(node.Tag) { totalFilt++ ; continue }
				fp := fmt.Sprintf("%s:%d:%s", node.Server, node.ServerPort, node.Tag)
				if seen[fp] { totalD++ ; continue }
				results = append(results, *node)
				seen[fp] = true
				count++
			}
		}
		fmt.Fprintf(os.Stderr, "   ✅ 解析成功: %d 个有效节点\n", count)
	}
	fmt.Fprintf(os.Stderr, "📊 汇总: 发现 %d | 过滤 %d | 去重 %d | 最终保留 %d\n", 
		totalF, totalFilt, totalD, len(results))
	return results
}

func injectToTemplate(oConf *orderedmap.OrderedMap, extra ExtraConfig, nodes []converter.SingBoxOutbound) *orderedmap.OrderedMap {
	var allProxyTags []string
	for _, n := range nodes { allProxyTags = append(allProxyTags, n.Tag) }

	var regionGroupOutbounds []converter.SingBoxOutbound
	var allRegionGroupTags []string
	for _, regConf := range extra.Regions {
		if len(regConf) < 2 { continue }
		reg, _ := regexp.Compile("(?i)" + regConf[0])
		var matched []string
		for _, t := range allProxyTags {
			if reg.MatchString(t) { matched = append(matched, t) }
		}
		if len(matched) > 0 {
			group := converter.SingBoxOutbound{
				Type: "urltest", Tag: regConf[1], Outbounds: matched,
				URL: "https://www.gstatic.com/generate_204", Interval: "3m", Tolerance: 150,
			}
			regionGroupOutbounds = append(regionGroupOutbounds, group)
			allRegionGroupTags = append(allRegionGroupTags, group.Tag)
		}
	}

	if rawOuts, exists := oConf.Get("outbounds"); exists {
		outList := rawOuts.([]interface{})
		var finalOutbounds []interface{}
		for _, item := range outList {
			if str, ok := item.(string); ok {
				if str == "<dynamic-region-groups>" {
					for _, rg := range regionGroupOutbounds { finalOutbounds = append(finalOutbounds, rg) }
				} else { finalOutbounds = append(finalOutbounds, str) }
				continue
			}
			if obj, ok := item.(orderedmap.OrderedMap); ok {
				if rawSub, exists := obj.Get("outbounds"); exists {
					subSlice := rawSub.([]interface{})
					var newSub []string
					for _, s := range subSlice {
						sStr, _ := s.(string)
						switch sStr {
						case "<all-proxies>": newSub = append(newSub, allProxyTags...)
						case "<all-region-groups>": newSub = append(newSub, allRegionGroupTags...)
						default: newSub = append(newSub, sStr)
						}
					}
					obj.Set("outbounds", newSub)
				}
				finalOutbounds = append(finalOutbounds, obj)
			}
		}
		for _, n := range nodes { finalOutbounds = append(finalOutbounds, n) }
		oConf.Set("outbounds", finalOutbounds)
	}

	oConf.Delete("_extra")
	return oConf
}

func writeToTarget(content, path, label string) {
	if path == "SKIP" { return }
	if path == "" || path == "-" {
		fmt.Println(content)
	} else {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "❌ 错误: 写入%s失败: %v\n", label, err)
		} else {
			fmt.Fprintf(os.Stderr, "✅ %s已保存至: %s\n", label, path)
		}
	}
}

func loadTemplate(path string) *orderedmap.OrderedMap {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 错误: 无法读取模板 %s\n", path)
		os.Exit(1)
	}
	o := orderedmap.New()
	if err := json.Unmarshal(data, &o); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 错误: 解析模板内容失败: %v\n", err)
		os.Exit(1)
	}
	return o
}

func getExtra(o *orderedmap.OrderedMap) ExtraConfig {
	var e ExtraConfig
	if v, exists := o.Get("_extra"); exists {
		b, _ := json.Marshal(v)
		json.Unmarshal(b, &e)
	}
	return e
}

func fixGoJsonStyle(input string) string {
	r := strings.NewReplacer("\\u0026", "&", "\\u003c", "<", "\\u003e", ">")
	output := r.Replace(input)
	re := regexp.MustCompile(`\[\s+([^\[\]\n]+)\s+\]`)
	output = re.ReplaceAllString(output, `[$1]`)
	return output
}

func fetchSubscription(url string) string {
	resp, err := http.Get(url)
	if err != nil { return "" }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) { if f.Name == name { found = true } })
	return found
}
