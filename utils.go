package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func formatURL(urls []string) []string {
	modifiedURLs := make([]string, 0, len(urls))

	for _, url := range urls {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}

		modifiedURLs = append(modifiedURLs, url)
	}
	return modifiedURLs
}

func readFile(fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.ReplaceAll(scanner.Text(), " ", "")
		if urlValidation.MatchString(url) {
			allURLs = append(allURLs, url)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
	}
}

func listS3BucketFiles(bucketURLs []string) {
	var wg sync.WaitGroup
	var scannable []string
	var notScannable []string
	var listURL fileListEntry
	var totalFiles = 0
	var totalIntFiles = 0

	var bucketFiles [][]string
	var bucketSizes [][]string

	for _, bucketURL := range bucketURLs {
		var allFiles []string
		var intFiles []string
		wg.Add(1)
		go func(bucketURL string) {
			defer wg.Done()
			// Make HTTP request to S3 bucket URL
			resp, err := http.Get(bucketURL)
			if err != nil {
				notScannable = append(notScannable, bucketURL)
				bucketlootOutput.Errors = append(bucketlootOutput.Errors, bucketURL+" encountered an error during the GET request: "+err.Error())
				return
			}
			defer resp.Body.Close()

			// Check response status code for errors
			if resp.StatusCode != http.StatusOK {
				notScannable = append(notScannable, bucketURL)
				return
			}

			// Read response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				notScannable = append(notScannable, bucketURL)
				return
			}

			// CHECK IF FULLSCAN FLAG IS TRUE, IF YES TRY THE AWS MODULE FIRST, ELSE USE GET REQUEST DATA

			if *fullScan {
				fmt.Println("Listing files using Full Mode...")
				//CHECKS FOR PLATFORMS
				awsHeader := resp.Header.Get("X-Amz-Bucket-Region")

				//CHECK IF THE SET BUCKET IS AN AWS-POWERED BUCKET
				if awsHeader != "" {
					fmt.Println("\nAWS S3 Bucket detected!")
					if awsCreds == "AccessKey:SecretKey" || !strings.Contains(awsCreds, ":") {
						fmt.Println("Invalid S3 credentials provided! Either use the correct credentials or re-run the scan without the full mode.")
						fmt.Println("Switching back to scrape mode...")
						bucketFiles = bucketFileRE.FindAllStringSubmatch(string(body), -1)
						bucketSizes = bucketSizeRE.FindAllStringSubmatch(string(body), -1)
					} else {
						awsBucketNameRes := awsBucketNameRe.FindAllStringSubmatch(string(body), -1)
						if awsBucketNameRes != nil {
							awsBucketName := awsBucketNameRes[0][1]
							awsKeys := strings.Split(awsCreds, ":")

							// Initialize a new AWS session
							sess, err := session.NewSession(&aws.Config{
								Region:      aws.String(awsHeader), // Provide the appropriate AWS region
								Credentials: credentials.NewStaticCredentials(awsKeys[0], awsKeys[1], ""),
							})
							if err != nil {
								fmt.Println("Failed to create session:", err)
								return
							}

							// Create a new S3 service client
							svc := s3.New(sess)

							// Retrieve the list of objects in the bucket
							params := &s3.ListObjectsInput{
								Bucket:  aws.String(awsBucketName),
								MaxKeys: aws.Int64(1000),
							}
							err = svc.ListObjectsPages(params, func(page *s3.ListObjectsOutput, lastPage bool) bool {
								for _, obj := range page.Contents {
									// Perform your desired operations with each object here
									filePath := *obj.Key
									fileSize := fmt.Sprintf("%d", *obj.Size)

									// Append the values to the respective 2D arrays
									bucketFiles = append(bucketFiles, []string{"", filePath})
									bucketSizes = append(bucketSizes, []string{"", fileSize})
								}
								return !lastPage
							})
							if err != nil {
								if _, ok := err.(awserr.Error); ok {
									bucketlootOutput.Errors = append(bucketlootOutput.Errors, string(err.Error()))
									fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode...")
									bucketFiles = bucketFileRE.FindAllStringSubmatch(string(body), -1)
									bucketSizes = bucketSizeRE.FindAllStringSubmatch(string(body), -1)
								} else {
									bucketlootOutput.Errors = append(bucketlootOutput.Errors, string(err.Error()))
									fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode...")
									bucketFiles = bucketFileRE.FindAllStringSubmatch(string(body), -1)
									bucketSizes = bucketSizeRE.FindAllStringSubmatch(string(body), -1)
								}
							}
						} else {
							fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode...")
							bucketFiles = bucketFileRE.FindAllStringSubmatch(string(body), -1)
							bucketSizes = bucketSizeRE.FindAllStringSubmatch(string(body), -1)
						}
					}
				} else {
					fmt.Println("Unknown platform! Switching back to scrape mode...")
					bucketFiles = bucketFileRE.FindAllStringSubmatch(string(body), -1)
					bucketSizes = bucketSizeRE.FindAllStringSubmatch(string(body), -1)
				}
			} else {
				// Parse HTML to extract S3 object keys
				bucketFiles = bucketFileRE.FindAllStringSubmatch(string(body), -1)
				bucketSizes = bucketSizeRE.FindAllStringSubmatch(string(body), -1)
			}
			for i := 0; i < len(bucketFiles) && i < len(bucketSizes); i++ {
				bucketFile := bucketFiles[i]
				bucketFileSize := bucketSizes[i]
				isBlacklisted = 0
				for _, blacklistExtension := range blacklistExtensions {
					if strings.Contains(bucketFile[1], blacklistExtension) {
						isBlacklisted = 1
						break
					}
				}
				if isBlacklisted == 0 {
					if maxFileSize != "" {
						buckfileSize, err := strconv.ParseInt(bucketFileSize[1], 10, 64)
						if err == nil {
							maxbucketfilesize, err := strconv.ParseInt(maxFileSize, 10, 64)
							if err == nil {
								if buckfileSize <= maxbucketfilesize {
									intFiles = append(intFiles, bucketURL+bucketFile[1])
									totalIntFiles += 1
								}
							}
						}
					} else {
						intFiles = append(intFiles, bucketURL+bucketFile[1])
						totalIntFiles += 1
					}
				}
				allFiles = append(allFiles, bucketURL+bucketFile[1])
				totalFiles += 1
			}

			if len(allFiles) > 0 {
				scannable = append(scannable, bucketURL)
				listURL = fileListEntry{URL: bucketURL, AllFiles: allFiles, IntFiles: intFiles}
				urlsFileList = append(urlsFileList, listURL)
				iniFileListData.ScanData = append(iniFileListData.ScanData, listURL)
			} else {
				notScannable = append(notScannable, bucketURL)
			}
		}(bucketURL)
	}
	wg.Wait()
	iniFileListData.Scannable = append(iniFileListData.Scannable, scannable...)
	iniFileListData.NotScannable = append(iniFileListData.NotScannable, notScannable...)
	iniFileListData.TotalFiles = totalFiles
	iniFileListData.TotalIntFiles = totalIntFiles
}

func toJSON() {
	jsonData, err := json.MarshalIndent(bucketlootOutput, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	} else {
		fmt.Println("\n" + string(jsonData))
		if saveOutput != "" {
			err := ioutil.WriteFile(saveOutput, jsonData, 0644)
			if err != nil {
				fmt.Println("error writing file:", err)
				return
			}

			return
		}
	}
}

func readCredsFile() {
	file, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalln("Error reading credentials.json file, Exiting! \n", err)
		return
	}
	var data platformCreds
	err = json.Unmarshal(file, &data)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	for _, entry := range data {
		if entry.Platform == "AWS" {
			awsCreds = entry.Credentials
		}
	}

}
