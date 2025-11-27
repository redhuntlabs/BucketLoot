package utils

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/redhuntlabs/bucketloot/internal/config"
)

// TakeInput processes command-line arguments and flags
func TakeInput() {
	config.SlowScan = flag.Bool("slow", false, "Set slow mode for the scan")
	config.FullScan = flag.Bool("full", false, "Go beyond the 1000 file scan limit [Requires additional setup!]")
	config.DigMode = flag.Bool("dig", false, "Extract and scan buckets from all targets that are not storage buckets!")
	config.Notify = flag.Bool("notify", false, "Notify using webhooks whenever the tool finds any security exposure")
	flag.StringVar(&config.KeywordSearch, "search", "", "Keyword(s) to look for during the scan. [Possible values -> keyword, keyword1:::keyword2, keywords.txt]")
	flag.StringVar(&config.MaxFileSize, "max-size", "", "Maximum file size (in bytes)")
	config.ErrorLogging = flag.Bool("log-errors", false, "Log errors in final output")
	flag.StringVar(&config.SaveOutput, "save", "", "Save tool output, should either end with .txt or .json [Default output file name is output.json]")
	flag.Parse()
	config.Args = flag.Args()

	if config.KeywordSearch != "" {
		if strings.Contains(config.KeywordSearch, ":::") {
			keywords := strings.Split(config.KeywordSearch, ":::")
			for _, keyword := range keywords {
				if strings.HasSuffix(keyword, ".txt") {
					file, err := os.Open(keyword)
					if err != nil {
						log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
					}
					defer file.Close()

					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						config.ScanKeywords = append(config.ScanKeywords, scanner.Text())
					}
				} else {
					config.ScanKeywords = append(config.ScanKeywords, keyword)
				}
			}
		} else {
			if strings.HasSuffix(config.KeywordSearch, ".txt") {
				file, err := os.Open(config.KeywordSearch)
				if err != nil {
					log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					config.ScanKeywords = append(config.ScanKeywords, scanner.Text())
				}
			} else {
				config.ScanKeywords = append(config.ScanKeywords, config.KeywordSearch)
			}
		}
	}

	if *config.FullScan {
		config.ReadCredsFile()
	}
}
