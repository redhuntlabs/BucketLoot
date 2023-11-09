package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
)

func takeInput() {
	slowScan = flag.Bool("slow", false, "Set slow mode for the scan")
	fullScan = flag.Bool("full", false, "Go beyond the 1000 file scan limit [Requires additional setup!]")
	digMode = flag.Bool("dig", false, "Extract and scan buckets from all targets that are not storage buckets!")
	notify = flag.Bool("notify", false, "Notify using webhooks whenever the tool finds security exposure")
	flag.StringVar(&keywordSearch, "search", "", "Keyword(s) to look for during the scan. [Possible values -> keyword, keyword1:::keyword2, keywords.txt]")
	flag.StringVar(&maxFileSize, "max-size", "", "Maximum file size (in bytes)")
	errorLogging = flag.Bool("log-errors", false, "Log errors in final output")
	flag.StringVar(&saveOutput, "save", "", "Save tool output, should either end with .txt or .json [Default output file name is output.json]")
	flag.Parse()
	args = flag.Args()

	if keywordSearch != "" {
		if strings.Contains(keywordSearch, ":::") {
			keywords := strings.Split(keywordSearch, ":::")
			for _, keyword := range keywords {
				if strings.HasSuffix(keyword, ".txt") {
					file, err := os.Open(keyword)
					if err != nil {
						log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
					}
					defer file.Close()

					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						scanKeywords = append(scanKeywords, scanner.Text())
					}
				} else {
					scanKeywords = append(scanKeywords, keyword)
				}
			}
		} else {
			if strings.HasSuffix(keywordSearch, ".txt") {
				file, err := os.Open(keywordSearch)
				if err != nil {
					log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					scanKeywords = append(scanKeywords, scanner.Text())
				}
			} else {
				scanKeywords = append(scanKeywords, keywordSearch)
			}
		}
	}

	if *fullScan {
		readCredsFile()
	}
}
