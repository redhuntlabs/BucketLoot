package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	takeInput()
	fmt.Println(banner, "")
	fmt.Println("\n ")
	if len(args) > 0 {
		fmt.Println("Processing arguments...")

		for i := 0; i < len(args); i++ {
			arg := args[i]
			if strings.HasSuffix(arg, ".txt") {
				fmt.Println("Reading file content from " + arg + "...")
				readFile(arg)
			} else if urlValidation.MatchString(arg) {
				allURLs = append(allURLs, arg)
			} else if arg == "slow" || arg == "-slow" || arg == "--slow" {
				*slowScan = true
			} else if arg == "dig" || arg == "-dig" || arg == "--dig" {
				*digMode = true
			} else if arg == "log-errors" || arg == "-log-errors" || arg == "--log-errors" {
				*errorLogging = true
			} else if arg == "full" || arg == "--full" || arg == "-full" {
				readCredsFile()
			} else if arg == "max-size" || arg == "-max-size" || arg == "--max-size" {
				if i+1 < len(args) {
					maxSizeStr := args[i+1]
					_, err := strconv.Atoi(maxSizeStr)
					if err != nil {
						log.Fatalln("Invalid max size:", maxSizeStr, ".. [Exiting!]")
					} else {
						maxFileSize = maxSizeStr
					}
				} else {
					log.Fatalln("Missing max size argument.. [Exiting!]")
				}
				i++ // Skip the next argument since it has been processed
			} else if arg == "search" || arg == "-search" || arg == "--search" {
				if i+1 < len(args) {
					if strings.Contains(args[i+1], ":::") {
						keywords := strings.Split(args[i+1], ":::")
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
						if strings.HasSuffix(args[i+1], ".txt") {
							file, err := os.Open(args[i+1])
							if err != nil {
								log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
							}
							defer file.Close()

							scanner := bufio.NewScanner(file)
							for scanner.Scan() {
								scanKeywords = append(scanKeywords, scanner.Text())
							}
						} else {
							scanKeywords = append(scanKeywords, args[i+1])
						}
					}
				} else {
					log.Fatalln("Missing search argument.. [Exiting!]")
				}
				i++ // Skip the next argument since it has been processed
			} else if arg == "save" || arg == "-save" || arg == "--save" {
				if i+1 < len(args) {
					if strings.HasSuffix(args[i+1], ".txt") || strings.HasSuffix(args[i+1], ".json") {
						saveOutput = args[i+1]
					} else {
						saveOutput = "output.json"
					}
				} else {
					saveOutput = "output.json"
				}
				i++ // Skip the next argument since it has been processed
			}
		}
		allURLs = formatURL(allURLs)
		if len(allURLs) > 0 {
			listS3BucketFiles(allURLs)
			if len(iniFileListData.Scannable) > 0 {
				if len(iniFileListData.NotScannable) > 0 {
					bucketlootOutput.Skipped = iniFileListData.NotScannable
				}
				bucketlootOutput.Scanned = iniFileListData.Scannable
				fmt.Println("\n ")
				fmt.Println("Discovered a total of " + strconv.Itoa(iniFileListData.TotalFiles) + " bucket files...")
				fmt.Println("Total bucket files of interest: " + strconv.Itoa(iniFileListData.TotalIntFiles))
				fmt.Println("\n ")
				if *slowScan {
					fmt.Println("Starting to scan the files... [SLOW]")
				} else {
					fmt.Println("Starting to scan the files... [FAST]")
				}
				for _, bucketEntry := range iniFileListData.ScanData {
					if *slowScan {
						scanS3FilesSlow(bucketEntry.IntFiles, bucketEntry.URL)
					} else {
						scanS3FilesFast(bucketEntry.IntFiles, bucketEntry.URL)
					}
				}
				toJSON()
			} else {
				fmt.Println("Oops.. Looks like no interesting buckets were discovered! Aborting the scan...")
				bucketlootOutput.Skipped = iniFileListData.NotScannable
				toJSON()
			}
		} else {
			log.Fatalln("Looks like no valid URLs/domains were specified.. [Exiting!]")
		}
	} else {
		fmt.Println("Looks like no arguments were specified.. [Exiting!]")
	}
}
