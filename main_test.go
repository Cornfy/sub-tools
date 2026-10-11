package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCommandLineInterfaceHelperProcess(testContext *testing.T) {
	if os.Getenv("SUB_TOOL_CLI_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"sub-tool"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("sub-tool", flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestNodeGenerationLoadsExplicitTemplate(testContext *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("vless://00000000-0000-4000-8000-000000000000@example.org:443?security=reality&pbk=" + key + "#Keep\n" +
			"vless://00000000-0000-4000-8000-000000000000@example.org:443?security=reality&pbk=" + key + "#Filtered"))
	}))
	defer server.Close()
	temporaryTestDirectory := testContext.TempDir()
	templatePath := filepath.Join(temporaryTestDirectory, "custom-template.json")
	template, operationError := json.Marshal(map[string]any{
		"_extra":    map[string]any{"sub_urls": [][]string{{"Synthetic", server.URL}}, "filter_keywords": "Filtered"},
		"outbounds": []any{map[string]any{"type": "selector", "tag": "Proxy", "outbounds": []string{"<all-proxies>"}}},
	})
	if operationError != nil {
		testContext.Fatal(operationError)
	}
	if operationError = os.WriteFile(templatePath, template, 0600); operationError != nil {
		testContext.Fatal(operationError)
	}
	for _, cliOverride := range []bool{false, true} {
		name := "template subscription"
		if cliOverride {
			name = "CLI subscription override"
		}
		testContext.Run(name, func(testContext *testing.T) {
			outputPath := filepath.Join(temporaryTestDirectory, "nodes.json")
			configPath := filepath.Join(temporaryTestDirectory, "config.json")
			commandLineArguments := []string{"-test.run=^TestCommandLineInterfaceHelperProcess$", "--", "-template", templatePath, "-node-gen", outputPath}
			if cliOverride {
				commandLineArguments = append(commandLineArguments, "-url", server.URL)
			}
			helperProcessCommand := exec.Command(os.Args[0], commandLineArguments...)
			helperProcessCommand.Dir = temporaryTestDirectory
			helperProcessCommand.Env = append(os.Environ(), "SUB_TOOL_CLI_TEST=1")
			output, operationError := helperProcessCommand.CombinedOutput()
			if operationError != nil {
				testContext.Fatalf("CLI failed: %v\n%s", operationError, output)
			}
			encodedJsonBytes, operationError := os.ReadFile(outputPath)
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			var nodes []struct {
				Tag string `json:"tag"`
			}
			if operationError = json.Unmarshal(encodedJsonBytes, &nodes); operationError != nil {
				testContext.Fatal(operationError)
			}
			if len(nodes) != 1 || nodes[0].Tag != "Keep" {
				testContext.Fatalf("template subscriptions or filters not loaded: %s", encodedJsonBytes)
			}
			helperProcessCommand = exec.Command(os.Args[0], append(commandLineArguments, "-config-gen", configPath)...)
			helperProcessCommand.Dir = temporaryTestDirectory
			helperProcessCommand.Env = append(os.Environ(), "SUB_TOOL_CLI_TEST=1")
			if output, operationError = helperProcessCommand.CombinedOutput(); operationError != nil {
				testContext.Fatalf("full config CLI failed: %v\n%s", operationError, output)
			}
			encodedJsonBytes, operationError = os.ReadFile(configPath)
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			var config struct {
				Extra     json.RawMessage `json:"_extra"`
				Outbounds []struct {
					Type      string   `json:"type"`
					Tag       string   `json:"tag"`
					Outbounds []string `json:"outbounds"`
				} `json:"outbounds"`
			}
			if operationError = json.Unmarshal(encodedJsonBytes, &config); operationError != nil {
				testContext.Fatal(operationError)
			}
			if config.Extra != nil || len(config.Outbounds) != 2 || len(config.Outbounds[0].Outbounds) != 1 || config.Outbounds[0].Outbounds[0] != "Keep" || config.Outbounds[1].Type != "vless" {
				testContext.Fatal("full configuration injection or private block removal failed")
			}
		})
	}
}

func TestCommandLineOutputPreservesNodeCredentials(testContext *testing.T) {
	password := `p@ss:word+/%40\u003c"<>&[  secret  ]`
	rawProtocolUri := (&url.URL{Scheme: "trojan", User: url.User(password), Host: "example.org:443", Fragment: "Synthetic"}).String()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(rawProtocolUri)) }))
	defer server.Close()
	temporaryTestDirectory := testContext.TempDir()
	templatePath := filepath.Join(temporaryTestDirectory, "template.json")
	if operationError := os.WriteFile(templatePath, []byte(`{"outbounds":[]}`), 0600); operationError != nil {
		testContext.Fatal(operationError)
	}
	nodePath := filepath.Join(temporaryTestDirectory, "nodes.json")
	configPath := filepath.Join(temporaryTestDirectory, "config.json")
	helperProcessCommand := exec.Command(os.Args[0], "-test.run=^TestCommandLineInterfaceHelperProcess$", "--", "-url", server.URL, "-template", templatePath, "-node-gen", nodePath, "-config-gen", configPath)
	helperProcessCommand.Dir = temporaryTestDirectory
	helperProcessCommand.Env = append(os.Environ(), "SUB_TOOL_CLI_TEST=1")
	if output, operationError := helperProcessCommand.CombinedOutput(); operationError != nil {
		testContext.Fatalf("CLI failed: %v\n%s", operationError, output)
	}
	for _, path := range []string{nodePath, configPath} {
		encodedJsonBytes, operationError := os.ReadFile(path)
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		var nodes []struct {
			Password string `json:"password"`
		}
		if path == nodePath {
			operationError = json.Unmarshal(encodedJsonBytes, &nodes)
		} else {
			var config struct {
				Outbounds []struct {
					Password string `json:"password"`
				} `json:"outbounds"`
			}
			operationError = json.Unmarshal(encodedJsonBytes, &config)
			nodes = config.Outbounds
		}
		if operationError != nil {
			testContext.Fatal("output JSON was corrupted by formatting")
		}
		if len(nodes) != 1 || nodes[0].Password != password {
			testContext.Fatal("credential changed in output JSON")
		}
	}
}
