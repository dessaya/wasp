package main

import (
	"fmt"
	"os"

	"github.com/iotaledger/hive.go/apputils/config"
	"github.com/iotaledger/hive.go/core/app"
	waspApp "github.com/iotaledger/wasp/core/app"
)

func createMarkdownFile(app *app.App, markdownHeaderPath string, markdownFilePath string, ignoreFlags map[string]struct{}, replaceTopicNames map[string]string) {

	markdownHeader := []byte(`<!---
!!! DO NOT MODIFY !!!

This file is auto-generated by the gendoc tool based on the source code of the app.
-->
`)

	if markdownHeaderPath != "" {
		var err error
		markdownHeaderFile, err := os.ReadFile(markdownHeaderPath)
		if err != nil {
			panic(err)
		}

		markdownHeader = append(markdownHeader, markdownHeaderFile...)
	}

	println(fmt.Sprintf("Create markdown file for %s...", app.Info().Name))
	md := config.GetConfigurationMarkdown(app.Config(), app.FlagSet(), ignoreFlags, replaceTopicNames)
	if err := os.WriteFile(markdownFilePath, append(markdownHeader, []byte(md)...), os.ModePerm); err != nil {
		panic(err)
	}
	println(fmt.Sprintf("Markdown file for %s stored: %s", app.Info().Name, markdownFilePath))
}

func createDefaultConfigFile(app *app.App, configFilePath string, ignoreFlags map[string]struct{}) {
	println(fmt.Sprintf("Create default configuration file for %s...", app.Info().Name))
	conf := config.GetDefaultAppConfigJSON(app.Config(), app.FlagSet(), ignoreFlags)
	if err := os.WriteFile(configFilePath, []byte(conf), os.ModePerm); err != nil {
		panic(err)
	}
	println(fmt.Sprintf("Default configuration file for %s stored: %s", app.Info().Name, configFilePath))
}

func main() {

	// MUST BE LOWER CASE
	ignoreFlags := make(map[string]struct{})

	replaceTopicNames := make(map[string]string)
	replaceTopicNames["app"] = "Application"
	replaceTopicNames["inx"] = "INX"
	replaceTopicNames["log"] = "Shutdown Log"
	replaceTopicNames["db"] = "Database"
	replaceTopicNames["jwt"] = "JWT Auth"
	replaceTopicNames["ip"] = "IP-based Auth"
	replaceTopicNames["basic"] = "Basic Auth"
	replaceTopicNames["webapi"] = "Web API"
	replaceTopicNames["wal"] = "Write-Ahead Logging"
	replaceTopicNames["rawBlocks"] = "Raw Blocks"
	replaceTopicNames["nanomsg"] = "nanomsg"

	application := waspApp.App()

	createMarkdownFile(
		application,
		"configuration_header.md",
		"../../documentation/docs/configuration.md",
		ignoreFlags,
		replaceTopicNames,
	)

	createDefaultConfigFile(
		application,
		"../../config_defaults.json",
		ignoreFlags,
	)
}