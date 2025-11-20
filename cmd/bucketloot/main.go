package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/umair9747/bucketloot/internal/config"
	"github.com/umair9747/bucketloot/internal/scanner"
	"github.com/umair9747/bucketloot/internal/utils"
)

func main() {
	// Initialize configuration
	if err := config.Initialize(); err != nil {
		log.Fatalln("Failed to initialize configuration:", err)
	}

	utils.TakeInput()
	fmt.Println(config.Banner, "")
	fmt.Println("\n ")

	if len(config.Args) > 0 {
		fmt.Println("Processing arguments...")

		for i := 0; i < len(config.Args); i++ {
			arg := config.Args[i]
			if strings.HasSuffix(arg, ".txt") {
				fmt.Println("Reading file content from " + arg + "...")
				utils.ReadFile(arg)
			} else if config.URLValidation.MatchString(arg) {
				config.AllURLs = append(config.AllURLs, arg)
			} else if arg == "slow" || arg == "-slow" || arg == "--slow" {
				*config.SlowScan = true
			} else if arg == "dig" || arg == "-dig" || arg == "--dig" {
				*config.DigMode = true
			} else if arg == "notify" || arg == "-notify" || arg == "--notify" {
				*config.Notify = true
			} else if arg == "log-errors" || arg == "-log-errors" || arg == "--log-errors" {
				*config.ErrorLogging = true
			} else if arg == "full" || arg == "--full" || arg == "-full" {
				config.ReadCredsFile()
			} else if arg == "max-size" || arg == "-max-size" || arg == "--max-size" {
				if i+1 < len(config.Args) {
					maxSizeStr := config.Args[i+1]
					_, err := strconv.Atoi(maxSizeStr)
					if err != nil {
						log.Fatalln("Invalid max size:", maxSizeStr, ".. [Exiting!]")
					} else {
						config.MaxFileSize = maxSizeStr
					}
				} else {
					log.Fatalln("Missing max size argument.. [Exiting!]")
				}
				i++ // Skip the next argument since it has been processed
			} else if arg == "search" || arg == "-search" || arg == "--search" {
				if i+1 < len(config.Args) {
					if strings.Contains(config.Args[i+1], ":::") {
						keywords := strings.Split(config.Args[i+1], ":::")
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
						if strings.HasSuffix(config.Args[i+1], ".txt") {
							file, err := os.Open(config.Args[i+1])
							if err != nil {
								log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
							}
							defer file.Close()

							scanner := bufio.NewScanner(file)
							for scanner.Scan() {
								config.ScanKeywords = append(config.ScanKeywords, scanner.Text())
							}
						} else {
							config.ScanKeywords = append(config.ScanKeywords, config.Args[i+1])
						}
					}
				} else {
					log.Fatalln("Missing search argument.. [Exiting!]")
				}
				i++ // Skip the next argument since it has been processed
			} else if arg == "save" || arg == "-save" || arg == "--save" {
				if i+1 < len(config.Args) {
					if strings.HasSuffix(config.Args[i+1], ".txt") || strings.HasSuffix(config.Args[i+1], ".json") {
						config.SaveOutput = config.Args[i+1]
					} else {
						config.SaveOutput = "output.json"
					}
				} else {
					config.SaveOutput = "output.json"
				}
				i++ // Skip the next argument since it has been processed
			}
		}

		if *config.Notify {
			notifyErr := config.LoadNotifyConfig()
			if notifyErr != nil {
				fmt.Println("Looks like these is some issue with your notifyconfig file:", notifyErr)
				utils.ToJSON()
				os.Exit(1)
			}
		}

		config.AllURLs = utils.FormatURL(config.AllURLs)
		if len(config.AllURLs) > 0 {
			scanner.ListS3BucketFiles(config.AllURLs)
			if len(config.IniFileListData.Scannable) > 0 {
				if len(config.IniFileListData.NotScannable) > 0 {
					config.BucketlootOutput.Skipped = config.IniFileListData.NotScannable
				}
				config.BucketlootOutput.Scanned = config.IniFileListData.Scannable
				fmt.Println("\n ")
				fmt.Println("Discovered a total of " + strconv.Itoa(config.IniFileListData.TotalFiles) + " bucket files...")
				fmt.Println("Total bucket files of interest: " + strconv.Itoa(config.IniFileListData.TotalIntFiles))
				fmt.Println("\n ")
				if *config.SlowScan {
					fmt.Println("Starting to scan the files... [SLOW]")
				} else {
					fmt.Println("Starting to scan the files... [FAST]")
				}
				for _, bucketEntry := range config.IniFileListData.ScanData {
					if *config.SlowScan {
						scanner.ScanS3FilesSlow(bucketEntry.IntFiles, bucketEntry.URL)
					} else {
						scanner.ScanS3FilesFast(bucketEntry.IntFiles, bucketEntry.URL)
					}
				}
				utils.ToJSON()
			} else {
				fmt.Println("Oops.. Looks like no interesting buckets were discovered! Aborting the scan...")
				config.BucketlootOutput.Skipped = config.IniFileListData.NotScannable
				utils.ToJSON()
			}
		} else {
			log.Fatalln("Looks like no valid URLs/domains were specified.. [Exiting!]")
		}
	} else {
		fmt.Println("Looks like no arguments were specified.. [Exiting!]")
	}
}
