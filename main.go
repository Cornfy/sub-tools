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

// SubscriptionUrlListContainer 存储从命令行输入的多个订阅源地址
type SubscriptionUrlListContainer []string

func (container *SubscriptionUrlListContainer) String() string {
	return strings.Join(*container, ", ")
}
func (container *SubscriptionUrlListContainer) Set(inputValue string) error {
	*container = append(*container, inputValue)
	return nil
}

// SingleTemplatePathArgument 确保转换模板路径参数在命令行中仅被指定一次
type SingleTemplatePathArgument struct {
	absoluteOrRelativePath string
	hasBeenExplicitlySet   bool
}

func (argument *SingleTemplatePathArgument) String() string { return argument.absoluteOrRelativePath }
func (argument *SingleTemplatePathArgument) Set(inputValue string) error {
	if argument.hasBeenExplicitlySet {
		return fmt.Errorf("错误: 只能指定一个模板文件")
	}
	argument.absoluteOrRelativePath = inputValue
	argument.hasBeenExplicitlySet = true
	return nil
}

// TemplateLogicControlConfiguration 定义了模板中 `_extra` 字段的结构，用于控制转换逻辑
type TemplateLogicControlConfiguration struct {
	RemoteSubscriptionUrls [][]string `json:"sub_urls"`
	NodeFilterRegexPattern string     `json:"filter_keywords"`
	RegionalGroupConfigs   [][]string `json:"regions"`
}

// ScheduledSubscriptionFetchTask 描述一个待执行的远程订阅抓取任务
type ScheduledSubscriptionFetchTask struct {
	SubscriptionLabel string
	SubscriptionUrl   string
}

func main() {
	var manuallySpecifiedSubscriptionUrls SubscriptionUrlListContainer
	flag.Var(&manuallySpecifiedSubscriptionUrls, "url", "远程订阅源地址 (可多次指定以合并)")

	var providedTemplateFilePath SingleTemplatePathArgument
	flag.Var(&providedTemplateFilePath, "template", "用于生成完整配置的 JSON 模板文件路径")

	destinationPathForRawNodeListJson := flag.String("node-gen", "SKIP", "输出纯节点列表 JSON 的文件路径")
	destinationPathForFullConfigurationJson := flag.String("config-gen", "SKIP", "输出完整 Sing-box 配置文件路径")
	displayVersionInformation := flag.Bool("version", false, "显示当前程序版本号")
	flag.BoolVar(displayVersionInformation, "v", false, "显示当前程序版本号 (简写)")

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

	if *displayVersionInformation {
		fmt.Printf("Sub-Tool Version: %s\n", version)
		return
	}

	shouldGenerateNodeListFile := checkIfCommandLineFlagWasExplicitlyProvided("node-gen")
	shouldGenerateFullConfigFile := checkIfCommandLineFlagWasExplicitlyProvided("config-gen")
	isAnyOutputDestinationDefined := shouldGenerateNodeListFile || shouldGenerateFullConfigFile
	isAnyInputSourceProvidedViaCli := len(manuallySpecifiedSubscriptionUrls) > 0 || providedTemplateFilePath.hasBeenExplicitlySet

	// 交互逻辑保护：如果用户既没给输入也没给输出参数，显示帮助
	if !isAnyOutputDestinationDefined && !isAnyInputSourceProvidedViaCli {
		flag.Usage()
		return
	}

	// 自动回退逻辑：如果未指定输出文件，默认将结果打印到标准输出 (Stdout)
	if !isAnyOutputDestinationDefined {
		fmt.Fprintln(os.Stderr, "💡 提示: 未指定具体的输出文件路径，默认开启标准输出 (Stdout) 模式")
		if providedTemplateFilePath.hasBeenExplicitlySet {
			shouldGenerateFullConfigFile = true
			*destinationPathForFullConfigurationJson = "-"
		} else {
			shouldGenerateNodeListFile = true
			*destinationPathForRawNodeListJson = "-"
		}
	}

	var parsedTemplateAsOrderedMap *orderedmap.OrderedMap
	var extractedControlLogicConfig TemplateLogicControlConfiguration
	finalEffectiveTemplatePath := providedTemplateFilePath.absoluteOrRelativePath

	if providedTemplateFilePath.hasBeenExplicitlySet {
		fmt.Fprintf(os.Stderr, "📂 已加载用户指定的模板文件: %s\n", finalEffectiveTemplatePath)
	}

	// 完整配置生成前的准备：解析模板与提取控制逻辑
	if shouldGenerateFullConfigFile {
		if finalEffectiveTemplatePath == "" && !checkIfDefaultTemplateFileExists() {
			fmt.Fprintln(os.Stderr, "❌ 错误: 生成完整配置必须提供模板文件。")
			os.Exit(1)
		}
		if finalEffectiveTemplatePath == "" {
			finalEffectiveTemplatePath = "template.json"
			fmt.Fprintln(os.Stderr, "⚠️  未指定模板文件，自动尝试回退至当前目录下的 template.json")
		}
		parsedTemplateAsOrderedMap = readAndParseJsonTemplateIntoOrderedMap(finalEffectiveTemplatePath)
		extractedControlLogicConfig = extractExtraControlConfigurationFromTemplate(parsedTemplateAsOrderedMap)
	}

	// 过滤规则静默加载：如果仅生成节点列表，尝试从默认模板中提取过滤关键字
	if shouldGenerateNodeListFile && !shouldGenerateFullConfigFile && checkIfDefaultTemplateFileExists() && finalEffectiveTemplatePath == "" {
		fmt.Fprintln(os.Stderr, "ℹ️  检测到 template.json，已自动加载其中的过滤规则")
		extractedControlLogicConfig = extractExtraControlConfigurationFromTemplate(readAndParseJsonTemplateIntoOrderedMap("template.json"))
	}

	// --- 订阅源任务归一化 ---
	var subscriptionFetchQueue []ScheduledSubscriptionFetchTask
	if len(manuallySpecifiedSubscriptionUrls) > 0 {
		for index, url := range manuallySpecifiedSubscriptionUrls {
			subscriptionFetchQueue = append(subscriptionFetchQueue, ScheduledSubscriptionFetchTask{
				SubscriptionLabel: fmt.Sprintf("CLI-Input-%d", index+1), 
				SubscriptionUrl:   url,
			})
		}
	} else {
		for _, urlPair := range extractedControlLogicConfig.RemoteSubscriptionUrls {
			if len(urlPair) >= 2 {
				subscriptionFetchQueue = append(subscriptionFetchQueue, ScheduledSubscriptionFetchTask{
					SubscriptionLabel: urlPair[0], 
					SubscriptionUrl:   urlPair[1],
				})
			}
		}
	}

	if len(subscriptionFetchQueue) == 0 {
		fmt.Fprintln(os.Stderr, "❌ 错误: 未找到任何有效的远程订阅源地址。")
		os.Exit(1)
	}

	// 执行抓取与转换逻辑
	standardizedOutboundNodesList := fetchAndConvertProxiesFromRemoteSources(subscriptionFetchQueue, extractedControlLogicConfig)

	if len(standardizedOutboundNodesList) == 0 {
		fmt.Fprintln(os.Stderr, "❌ 错误: 在提供的所有订阅源中均未找到有效节点，操作已终止。")
		os.Exit(1)
	}

	// 输出动作 1: 生成纯节点 JSON 列表
	if shouldGenerateNodeListFile {
		fmt.Fprintln(os.Stderr, "📝 正在构建节点 JSON 列表...")
		nodeListJsonData, _ := json.MarshalIndent(standardizedOutboundNodesList, "", "  ")
		writeOutputContentToDestination(
			postProcessJsonOutputToCorrectEncodingAndFormatting(string(nodeListJsonData)),
			*destinationPathForRawNodeListJson,
			"节点列表",
		)
	}

	// 输出动作 2: 执行模板注入生成完整 Sing-box 配置
	if shouldGenerateFullConfigFile {
		fmt.Fprintln(os.Stderr, "⚙️  正在执行占位符动态注入逻辑...")
		finalConfigResultMap := injectNodesAndGroupsIntoTemplate(
			parsedTemplateAsOrderedMap,
			extractedControlLogicConfig,
			standardizedOutboundNodesList,
		)

		var outputBuffer bytes.Buffer
		jsonEncoder := json.NewEncoder(&outputBuffer)
		jsonEncoder.SetEscapeHTML(false)
		jsonEncoder.SetIndent("", "  ")
		jsonEncoder.Encode(finalConfigResultMap)

		writeOutputContentToDestination(
			postProcessJsonOutputToCorrectEncodingAndFormatting(outputBuffer.String()),
			*destinationPathForFullConfigurationJson,
			"完整配置文件",
		)
	}
}

func fetchAndConvertProxiesFromRemoteSources(
	fetchTasks []ScheduledSubscriptionFetchTask,
	controlConfig TemplateLogicControlConfiguration,
) []converter.StandardSingBoxOutboundConfiguration {

	finalNodesCollection := []converter.StandardSingBoxOutboundConfiguration{}
	nodeUniqueFingerprintRegistry := make(map[string]bool)

	var aggregateFoundCount, aggregateFilteredCount, aggregateDuplicateCountInt int

	var filterRegexCompiler *regexp.Regexp
	if controlConfig.NodeFilterRegexPattern != "" {
		filterRegexCompiler = regexp.MustCompile("(?i)" + controlConfig.NodeFilterRegexPattern)
	}

	for taskIndex, task := range fetchTasks {
		fmt.Fprintf(os.Stderr, "🌐 [%d/%d] 正在请求远程订阅: [%s]\n", taskIndex+1, len(fetchTasks), task.SubscriptionLabel)

		rawEncryptedContent := downloadRawContentFromRemoteUrl(task.SubscriptionUrl)
		if rawEncryptedContent == "" {
			fmt.Fprintln(os.Stderr, "   ⚠️  读取失败: 响应内容为空或请求出错")
			continue
		}

		// 尝试进行鲁棒性 Base64 解码
		decodedContent, decodingError := converter.AttemptRobustBase64DecodingOfSubscriptionContent(rawEncryptedContent)
		if decodingError != nil {
			decodedContent = rawEncryptedContent // 如果解码失败，尝试作为明文解析
		}

		var sourceParsed, sourceFiltered, sourceDuplicates, sourceAdded int
		contentLines := strings.Split(decodedContent, "\n")

		for _, singleLine := range contentLines {
			sanitizedLine := strings.TrimSpace(singleLine)
			if sanitizedLine == "" { continue }

			nodeObject, conversionError := converter.ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(sanitizedLine)
			if conversionError != nil || nodeObject == nil { continue }

			sourceParsed++

			// 匹配过滤逻辑
			if filterRegexCompiler != nil && filterRegexCompiler.MatchString(nodeObject.Tag) {
				sourceFiltered++
				continue
			}

			// 去重逻辑：基于 服务器+端口+名称 生成指纹
			uniqueFingerprint := fmt.Sprintf("%s:%d:%s", nodeObject.ServerAddress, nodeObject.ServerPort, nodeObject.Tag)
			if nodeUniqueFingerprintRegistry[uniqueFingerprint] {
				sourceDuplicates++
				continue
			}

			finalNodesCollection = append(finalNodesCollection, *nodeObject)
			nodeUniqueFingerprintRegistry[uniqueFingerprint] = true
			sourceAdded++
		}

		aggregateFoundCount += sourceParsed
		aggregateFilteredCount += sourceFiltered
		aggregateDuplicateCountInt += sourceDuplicates

		fmt.Fprintf(os.Stderr, "   ✅ 处理统计: 解析 %d | 过滤 %d | 重复 %d | 新增 %d\n",
			sourceParsed, sourceFiltered, sourceDuplicates, sourceAdded)
	}

	fmt.Fprintf(os.Stderr, "📊 最终汇总: 总发现 %d | 已过滤 %d | 已去重 %d | 最终保留 %d 个节点\n",
		aggregateFoundCount, aggregateFilteredCount, aggregateDuplicateCountInt, len(finalNodesCollection))

	return finalNodesCollection
}

func injectNodesAndGroupsIntoTemplate(
	templateMap *orderedmap.OrderedMap,
	controlConfig TemplateLogicControlConfiguration,
	availableNodes []converter.StandardSingBoxOutboundConfiguration,
) *orderedmap.OrderedMap {

	var allNodeTagsList []string
	for _, node := range availableNodes {
		allNodeTagsList = append(allNodeTagsList, node.Tag)
	}

	var dynamicRegionGroupsCollection []converter.StandardSingBoxOutboundConfiguration
	var allRegionGroupTagsList []string

	// 处理动态区域分组逻辑
	for _, regionRule := range controlConfig.RegionalGroupConfigs {
		if len(regionRule) < 2 { continue }
		groupLabel, regexPattern := regionRule[0], regionRule[1]
		
		regionRegex, _ := regexp.Compile("(?i)" + regexPattern)
		
		var matchedNodeTags []string
		for _, tag := range allNodeTagsList {
			if regionRegex.MatchString(tag) {
				matchedNodeTags = append(matchedNodeTags, tag)
			}
		}

		if len(matchedNodeTags) > 0 {
			newGroup := converter.StandardSingBoxOutboundConfiguration{
				Type: "urltest", 
				Tag: groupLabel, 
				Outbounds: matchedNodeTags,
				ConnectivityTestUrl: "https://www.gstatic.com/generate_204", 
				TestInterval: "3m", 
				ToleranceValue: 150,
			}
			dynamicRegionGroupsCollection = append(dynamicRegionGroupsCollection, newGroup)
			allRegionGroupTagsList = append(allRegionGroupTagsList, groupLabel)
		}
	}

	// 在模板的 outbounds 数组中寻找并替换占位符
	if rawOutboundsInterface, exists := templateMap.Get("outbounds"); exists {
		originalOutboundList := rawOutboundsInterface.([]interface{})
		var newlyConstructedOutboundList []interface{}

		for _, item := range originalOutboundList {
			// 处理纯字符串形式的占位符 (例如单独的 "<dynamic-region-groups>")
			if placeholderString, isString := item.(string); isString {
				if placeholderString == "<dynamic-region-groups>" {
					for _, rg := range dynamicRegionGroupsCollection {
						newlyConstructedOutboundList = append(newlyConstructedOutboundList, rg)
					}
				} else {
					newlyConstructedOutboundList = append(newlyConstructedOutboundList, placeholderString)
				}
				continue
			}

			// 处理对象形式的出站项 (如 selector 类型的分组)
			if outboundObjectAsMap, isMap := item.(orderedmap.OrderedMap); isMap {
				if subOutboundsInterface, exists := outboundObjectAsMap.Get("outbounds"); exists {
					subOutboundTagsList := subOutboundsInterface.([]interface{})
					var expandedOutboundTags []string
					
					for _, tagInterface := range subOutboundTagsList {
						tagName, _ := tagInterface.(string)
						switch tagName {
						case "<all-proxies>":
							expandedOutboundTags = append(expandedOutboundTags, allNodeTagsList...)
						case "<all-region-groups>":
							expandedOutboundTags = append(expandedOutboundTags, allRegionGroupTagsList...)
						default:
							expandedOutboundTags = append(expandedOutboundTags, tagName)
						}
					}
					outboundObjectAsMap.Set("outbounds", expandedOutboundTags)
				}
				newlyConstructedOutboundList = append(newlyConstructedOutboundList, outboundObjectAsMap)
			}
		}

		// 最后将所有解析出的底层节点追加到 outbounds 列表末尾
		for _, node := range availableNodes {
			newlyConstructedOutboundList = append(newlyConstructedOutboundList, node)
		}
		templateMap.Set("outbounds", newlyConstructedOutboundList)
	}

	// 移除模板中的辅助配置项，避免导出到最终配置
	templateMap.Delete("_extra")
	return templateMap
}

func writeOutputContentToDestination(finalContentBody, destinationPath, contentLabel string) {
	if destinationPath == "SKIP" { return }
	if destinationPath == "" || destinationPath == "-" {
		fmt.Println(finalContentBody)
		return
	}
	
	writeError := os.WriteFile(destinationPath, []byte(finalContentBody), 0644)
	if writeError != nil {
		fmt.Fprintf(os.Stderr, "❌ 错误: 写入%s到文件失败: %v\n", contentLabel, writeError)
	} else {
		fmt.Fprintf(os.Stderr, "✅ %s已成功保存至: %s\n", contentLabel, destinationPath)
	}
}

func readAndParseJsonTemplateIntoOrderedMap(filePath string) *orderedmap.OrderedMap {
	fileBytes, readError := os.ReadFile(filePath)
	if readError != nil {
		fmt.Fprintf(os.Stderr, "❌ 错误: 无法读取指定的模板文件 %s\n", filePath)
		os.Exit(1)
	}
	targetMap := orderedmap.New()
	json.Unmarshal(fileBytes, &targetMap)
	return targetMap
}

func extractExtraControlConfigurationFromTemplate(orderedTemplate *orderedmap.OrderedMap) TemplateLogicControlConfiguration {
	var controlConfig TemplateLogicControlConfiguration
	if extraNode, exists := orderedTemplate.Get("_extra"); exists {
		jsonBytes, _ := json.Marshal(extraNode)
		json.Unmarshal(jsonBytes, &controlConfig)
	}
	return controlConfig
}

// postProcessJsonOutputToCorrectEncodingAndFormatting 修复 JSON 转义后的 HTML 字符并美化数组排版
func postProcessJsonOutputToCorrectEncodingAndFormatting(jsonInput string) string {
	htmlCharacterReplacer := strings.NewReplacer("\\u0026", "&", "\\u003c", "<", "\\u003e", ">")
	arrayCompactRegex := regexp.MustCompile(`\[\s+([^\[\]\n]+)\s+\]`)
	
	unescapedJson := htmlCharacterReplacer.Replace(jsonInput)
	return arrayCompactRegex.ReplaceAllString(unescapedJson, `[$1]`)
}

func downloadRawContentFromRemoteUrl(targetUrl string) string {
	httpClientResponse, requestError := http.Get(targetUrl)
	if requestError != nil { return "" }
	defer httpClientResponse.Body.Close()
	
	responseBodyBytes, _ := io.ReadAll(httpClientResponse.Body)
	return string(responseBodyBytes)
}

func checkIfCommandLineFlagWasExplicitlyProvided(flagName string) bool {
	wasProvided := false
	flag.Visit(func(f *flag.Flag) { 
		if f.Name == flagName { wasProvided = true } 
	})
	return wasProvided
}

func checkIfDefaultTemplateFileExists() bool {
	fileInfo, checkError := os.Stat("template.json")
	return checkError == nil && !fileInfo.IsDir()
}
