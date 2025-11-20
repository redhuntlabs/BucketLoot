package scanner

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/fatih/color"
	tld "github.com/jpillora/go-tld"

	"github.com/umair9747/bucketloot/internal/config"
	"github.com/umair9747/bucketloot/internal/types"
	"github.com/umair9747/bucketloot/internal/utils"
)

var tempDir = ".temp"
var tempFileSuffix = "temp_s3_file_"

// ScanS3FilesSlow performs slow sequential scanning of S3 files
func ScanS3FilesSlow(fileURLs []string, bucketURL string) error {
	var errors []error

	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}

	var bucketScanRes types.BucketLootResStruct
	bucketScanRes.BucketUrl = bucketURL

	for _, fileURL := range fileURLs {
		var (
			bucketLootAsset   types.BucketlootAssetStruct
			bucketLootSecret  types.BucketlootSecretStruct
			bucketLootFile    types.BucketlootSensitiveFileStruct
			bucketLootKeyword types.BucketlootKeywordStruct
			keywordDisc       int
		)

		tempFile, err := os.CreateTemp(tempDir, tempFileSuffix)
		if err != nil {
			errors = append(errors, fmt.Errorf("error creating temporary file: %v", err))
			continue
		}
		defer tempFile.Close()

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return nil
			},
		}

		resp, err := client.Get(fileURL)
		if err != nil {
			errors = append(errors, fmt.Errorf("error making HTTP request to S3 bucket file URL: %v", err))
			continue
		}
		defer resp.Body.Close()

		_, err = io.Copy(tempFile, resp.Body)
		if err != nil {
			errors = append(errors, fmt.Errorf("error copying response body to temporary file: %v", err))
			continue
		}

		body, err := os.ReadFile(tempFile.Name())
		if err != nil {
			errors = append(errors, fmt.Errorf("error reading content from the temporary file: %v", err))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == http.StatusNotFound {
				errors = append(errors, fmt.Errorf("s3 bucket file not found: %s", fileURL))
			} else if resp.StatusCode == http.StatusForbidden {
				errors = append(errors, fmt.Errorf("s3 bucket file is private: %s", fileURL))
			} else {
				errors = append(errors, fmt.Errorf("unexpected response status code from S3 bucket file URL: %d: %s", resp.StatusCode, fileURL))
			}
			continue
		}

		// Extract Secrets
		for _, rule := range config.Rules {
			reg := regexp.MustCompile(rule.Regex)
			if reg.MatchString(string(body)) {
				fmt.Printf("Discovered %v in %s\n", color.RedString("SECRET["+rule.Title+"]"), fileURL)
				bucketLootSecret.Name = rule.Title
				bucketLootSecret.URL = fileURL
				bucketLootSecret.Severity = rule.Severity
				bucketScanRes.Secrets = append(bucketScanRes.Secrets, bucketLootSecret)
				bucketLootSecret.Name = ""
				bucketLootSecret.URL = ""

				if *config.Notify {
					if config.Platforms[0].Discord != "" {
						err := utils.NotifyDiscord(config.Platforms[0].Discord, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+fileURL+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
						if err != nil {
							if strings.Contains(err.Error(), "204") {
								fmt.Println("Notified successfully!")
							} else {
								fmt.Println("Couldn't notify!")
							}
							errors = append(errors, fmt.Errorf("error notifying! %s", err))
						}
					}
					if config.Platforms[1].Slack != "" {
						err := utils.NotifySlack(config.Platforms[1].Slack, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+fileURL+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
						if err != nil {
							if strings.Contains(err.Error(), "200") {
								fmt.Println("Notified successfully! [SLACK]")
							} else {
								fmt.Println("Couldn't notify! [SLACK]")
							}
							errors = append(errors, fmt.Errorf("error notifying! %s", err))
						}
					}
				}
			}
		}

		// Look for potentially sensitive/vuln files
		for _, check := range config.VulnerableFileChecks {
			re, err := regexp.Compile(check.Match)
			if err != nil {
				errors = append(errors, fmt.Errorf("error compiling vuln files regex %s", err))
				continue
			}

			if re != nil {
				if re.MatchString(fileURL) {
					fmt.Printf("Discovered %v in %s\n", color.YellowString("POTENTIALLY SENSITIVE FILE["+check.Name+"]"), fileURL)
					bucketLootFile.Name = check.Name
					bucketLootFile.URL = fileURL
					bucketScanRes.SensitiveFiles = append(bucketScanRes.SensitiveFiles, bucketLootFile)
					bucketLootFile.Name = ""
					bucketLootFile.URL = ""

					if *config.Notify {
						if config.Platforms[0].Discord != "" {
							err := utils.NotifyDiscord(config.Platforms[0].Discord, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+fileURL+" | BUCKET URL: "+bucketURL)
							if err != nil {
								if strings.Contains(err.Error(), "204") {
									fmt.Println("Notified successfully!")
								} else {
									fmt.Println("Couldn't notify!")
								}
								errors = append(errors, fmt.Errorf("error notifying! %s", err))
							}
						}
						if config.Platforms[1].Slack != "" {
							err := utils.NotifySlack(config.Platforms[1].Slack, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+fileURL+" | BUCKET URL: "+bucketURL)
							if err != nil {
								if strings.Contains(err.Error(), "200") {
									fmt.Println("Notified successfully! [SLACK]")
								} else {
									fmt.Println("Couldn't notify! [SLACK]")
								}
								errors = append(errors, fmt.Errorf("error notifying! %s", err))
							}
						}
					}
				}
			}
		}

		// Extract URLs
		extURLs := config.URLRE.FindAllString(string(body), -1)
		config.URLAssets = append(config.URLAssets, extURLs...)
		if len(extURLs) > 0 {
			fmt.Printf("Discovered %v in %s\n", color.BlueString("URL(s)"), fileURL)
		}

		// Extract Domains - Subdomains
		for _, u := range extURLs {
			bucketLootAsset.URL = u
			asset, err := tld.Parse(u)
			if err == nil {
				config.DomAssets = append(config.DomAssets, asset.Domain+"."+asset.TLD)
				bucketLootAsset.Domain = asset.Domain + "." + asset.TLD
				if asset.Subdomain != "" {
					config.SubAssets = append(config.SubAssets, asset.Subdomain+"."+asset.Domain+"."+asset.TLD)
					bucketLootAsset.Subdomain = asset.Subdomain + "." + asset.Domain + "." + asset.TLD
				}
			}
			bucketScanRes.Assets = append(bucketScanRes.Assets, bucketLootAsset)
			bucketLootAsset.URL = ""
			bucketLootAsset.Domain = ""
			bucketLootAsset.Subdomain = ""
		}

		// Search for user defined keywords
		for _, keyword := range config.ScanKeywords {
			keywordRe := regexp.MustCompile(keyword)
			if keywordRe.MatchString(fileURL) {
				bucketLootKeyword.Keyword = keyword
				bucketLootKeyword.URL = fileURL
				bucketLootKeyword.Type = "FilePath"
				bucketScanRes.Keywords = append(bucketScanRes.Keywords, bucketLootKeyword)
				keywordDisc = 1
			}
			if keywordRe.MatchString(string(body)) {
				bucketLootKeyword.Keyword = keyword
				bucketLootKeyword.URL = fileURL
				bucketLootKeyword.Type = "FileContent"
				bucketScanRes.Keywords = append(bucketScanRes.Keywords, bucketLootKeyword)
				keywordDisc = 1
			}
		}

		if keywordDisc == 1 {
			fmt.Printf("Discovered %v in %s\n", color.GreenString("Keyword(s)"), fileURL)
		}
	}

	os.RemoveAll(tempDir)

	config.BucketlootOutput.Results = append(config.BucketlootOutput.Results, bucketScanRes)
	if len(errors) > 0 {
		for _, err := range errors {
			if *config.ErrorLogging {
				config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, string(err.Error()))
			}
		}
	}

	return nil
}

// ScanS3FilesFast performs fast concurrent scanning of S3 files
func ScanS3FilesFast(fileURLs []string, bucketURL string) error {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var errors []error
	var downloadedFiles []string

	var (
		bucketLootAsset   types.BucketlootAssetStruct
		bucketLootSecret  types.BucketlootSecretStruct
		bucketLootKeyword types.BucketlootKeywordStruct
		bucketLootFile    types.BucketlootSensitiveFileStruct
		keywordDisc       int
	)

	os.RemoveAll(tempDir)

	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}

	bucketScanRes := types.BucketLootResStruct{
		BucketUrl: bucketURL,
	}

	for _, fileURL := range fileURLs {
		wg.Add(1)

		go func(url string) {
			defer wg.Done()

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return nil
				},
			}

			resp, err := client.Get(url)
			if err != nil {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("error making HTTP request to S3 bucket file URL: %v", err))
				mutex.Unlock()
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				mutex.Lock()
				if resp.StatusCode == http.StatusNotFound {
					errors = append(errors, fmt.Errorf("s3 bucket file not found: %s", url))
				} else if resp.StatusCode == http.StatusForbidden {
					errors = append(errors, fmt.Errorf("s3 bucket file is private: %s", url))
				} else {
					errors = append(errors, fmt.Errorf("unexpected response status code from S3 bucket file URL: %d: %s", resp.StatusCode, url))
				}
				mutex.Unlock()
				return
			}

			tempFile, err := os.CreateTemp(tempDir, tempFileSuffix)
			if err != nil {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("error creating temporary file: %v", err))
				mutex.Unlock()
				return
			}
			defer tempFile.Close()

			_, err = io.Copy(tempFile, resp.Body)
			if err != nil {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("error copying response body to temporary file: %v", err))
				mutex.Unlock()
				return
			}

			tempFile.WriteString("\n" + base64.StdEncoding.EncodeToString([]byte(url)))
			tempFile.Close()

			mutex.Lock()
			downloadedFiles = append(downloadedFiles, tempFile.Name())
			mutex.Unlock()

		}(fileURL)
	}

	wg.Wait()

	for _, filePath := range downloadedFiles {
		wg.Add(1)

		go func(filePath string) {
			defer wg.Done()

			body, err := os.ReadFile(filePath)
			lines := strings.Split(string(body), "\n")
			urlByte, err := base64.StdEncoding.DecodeString(lines[len(lines)-1])
			url := string(urlByte)

			if err != nil {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("error reading response body from S3 bucket file URL: %v: %s", err, url))
				mutex.Unlock()
				return
			}
			for _, rule := range config.Rules {
				reg := regexp.MustCompile(rule.Regex)
				if reg.MatchString(string(body)) {
					fmt.Printf("Discovered %v in %s\n", color.RedString("SECRET["+rule.Title+"]"), url)
					bucketLootSecret.Name = rule.Title
					bucketLootSecret.URL = url
					bucketLootSecret.Severity = rule.Severity
					mutex.Lock()
					bucketScanRes.Secrets = append(bucketScanRes.Secrets, bucketLootSecret)
					mutex.Unlock()
					bucketLootSecret.Name = ""
					bucketLootSecret.URL = ""

					if *config.Notify {
						if config.Platforms[0].Discord != "" {
							err := utils.NotifyDiscord(config.Platforms[0].Discord, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+url+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
							if err != nil {
								if strings.Contains(err.Error(), "204") {
									fmt.Println("Notified successfully! [DISCORD]")
								} else {
									fmt.Println("Couldn't notify! [DISCORD]")
								}
								errors = append(errors, fmt.Errorf("error notifying! %s", err))
							}
						}
						if config.Platforms[1].Slack != "" {
							err := utils.NotifySlack(config.Platforms[1].Slack, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+url+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
							if err != nil {
								if strings.Contains(err.Error(), "200") {
									fmt.Println("Notified successfully! [SLACK]")
								} else {
									fmt.Println("Couldn't notify! [SLACK]")
								}
								errors = append(errors, fmt.Errorf("error notifying! %s", err))
							}
						}
					}
				}
			}
			
			// Look for potentially sensitive/vuln files
			for _, check := range config.VulnerableFileChecks {
				re, err := regexp.Compile(check.Match)
				if err != nil {
					errors = append(errors, fmt.Errorf("error compiling vuln files regex %s", err))
					continue
				}

				if re != nil {
					if re.MatchString(url) {
						fmt.Printf("Discovered %v in %s\n", color.YellowString("POTENTIALLY SENSITIVE FILE["+check.Name+"]"), url)
						bucketLootFile.Name = check.Name
						bucketLootFile.URL = url
						mutex.Lock()
						bucketScanRes.SensitiveFiles = append(bucketScanRes.SensitiveFiles, bucketLootFile)
						mutex.Unlock()
						bucketLootFile.Name = ""
						bucketLootFile.URL = ""

						if *config.Notify {
							if config.Platforms[0].Discord != "" {
								err := utils.NotifyDiscord(config.Platforms[0].Discord, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+url+" | BUCKET URL: "+bucketURL)
								if err != nil {
									if strings.Contains(err.Error(), "204") {
										fmt.Println("Notified successfully! [DISCORD]")
									} else {
										fmt.Println("Couldn't notify! [DISCORD]")
									}
									errors = append(errors, fmt.Errorf("error notifying! %s", err))
								}
							}
							if config.Platforms[1].Slack != "" {
								err := utils.NotifySlack(config.Platforms[1].Slack, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+url+" | BUCKET URL: "+bucketURL)
								if err != nil {
									if strings.Contains(err.Error(), "200") {
										fmt.Println("Notified successfully! [SLACK]")
									} else {
										fmt.Println("Couldn't notify! [SLACK]")
									}
									errors = append(errors, fmt.Errorf("error notifying! %s", err))
								}
							}
						}
					}
				}
			}

			extURLs := config.URLRE.FindAllString(string(body), -1)
			mutex.Lock()
			config.URLAssets = append(config.URLAssets, extURLs...)
			mutex.Unlock()
			if len(extURLs) > 0 {
				fmt.Printf("Discovered %v in %s\n", color.BlueString("URL(s)"), url)
			}

			for _, u := range extURLs {
				bucketLootAsset.URL = u
				asset, err := tld.Parse(u)
				if err == nil {
					mutex.Lock()
					config.DomAssets = append(config.DomAssets, asset.Domain+"."+asset.TLD)
					bucketLootAsset.Domain = asset.Domain + "." + asset.TLD
					if asset.Subdomain != "" {
						config.SubAssets = append(config.SubAssets, asset.Subdomain+"."+asset.Domain+"."+asset.TLD)
						bucketLootAsset.Subdomain = asset.Subdomain + "." + asset.Domain + "." + asset.TLD
					}
					mutex.Unlock()
				}
				mutex.Lock()
				bucketScanRes.Assets = append(bucketScanRes.Assets, bucketLootAsset)
				mutex.Unlock()
				bucketLootAsset.URL = ""
				bucketLootAsset.Domain = ""
				bucketLootAsset.Subdomain = ""
			}

			for _, keyword := range config.ScanKeywords {
				keywordRe := regexp.MustCompile(keyword)
				if keywordRe.MatchString(url) {
					bucketLootKeyword.Keyword = keyword
					bucketLootKeyword.URL = url
					bucketLootKeyword.Type = "FilePath"
					mutex.Lock()
					bucketScanRes.Keywords = append(bucketScanRes.Keywords, bucketLootKeyword)
					keywordDisc = 1
					mutex.Unlock()
				}
				if keywordRe.MatchString(string(body)) {
					bucketLootKeyword.Keyword = keyword
					bucketLootKeyword.URL = url
					bucketLootKeyword.Type = "FileContent"
					mutex.Lock()
					bucketScanRes.Keywords = append(bucketScanRes.Keywords, bucketLootKeyword)
					keywordDisc = 1
					mutex.Unlock()
				}
			}

			if keywordDisc == 1 {
				fmt.Printf("Discovered %v in %s\n", color.GreenString("Keyword(s)"), url)
			}

		}(filePath)

	}

	wg.Wait()

	os.RemoveAll(tempDir)

	config.BucketlootOutput.Results = append(config.BucketlootOutput.Results, bucketScanRes)
	if len(errors) > 0 {
		for _, err := range errors {
			if *config.ErrorLogging {
				config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, string(err.Error()))
			}
		}
	}

	return nil
}

// ListFilesOtherURLs lists files from non-primary bucket URLs
func ListFilesOtherURLs(bucketURL string, fullScan bool) (otherbucketFiles [][]string, otherbucketSizes [][]string, err error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Get(bucketURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to retrieve data from %s. Status code: %d", bucketURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	var allFiles [][]string
	var allFileSizes [][]string

	if fullScan {
		fmt.Println("Listing files using Full Mode... [Other URLs]")
		awsHeader := resp.Header.Get("X-Amz-Bucket-Region")

		if awsHeader != "" {
			fmt.Println("\nAWS S3 Bucket detected!")
			if config.AWSCreds == "AccessKey:SecretKey" || !strings.Contains(config.AWSCreds, ":") {
				fmt.Println("Invalid S3 credentials provided! Either use the correct credentials or re-run the scan without the full mode. [Other URLs]")
				fmt.Println("Switching back to scrape mode... [Other URLs]")
				allFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
				allFileSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
			} else {
				awsBucketNameRes := config.AWSBucketNameRe.FindAllStringSubmatch(string(body), -1)
				if awsBucketNameRes != nil {
					awsBucketName := awsBucketNameRes[0][1]
					awsKeys := strings.Split(config.AWSCreds, ":")

					sess, err := session.NewSession(&aws.Config{
						Region:      aws.String(awsHeader),
						Credentials: credentials.NewStaticCredentials(awsKeys[0], awsKeys[1], ""),
					})
					if err != nil {
						fmt.Println("Failed to create session [Other URLs]:", err)
						return nil, nil, err
					}

					svc := s3.New(sess)

					params := &s3.ListObjectsInput{
						Bucket:  aws.String(awsBucketName),
						MaxKeys: aws.Int64(1000),
					}
					err = svc.ListObjectsPages(params, func(page *s3.ListObjectsOutput, lastPage bool) bool {
						for _, obj := range page.Contents {
							filePath := *obj.Key
							fileSize := fmt.Sprintf("%d", *obj.Size)

							allFiles = append(allFiles, []string{"", filePath})
							allFileSizes = append(allFileSizes, []string{"", fileSize})
						}
						return !lastPage
					})
					if err != nil {
						if _, ok := err.(awserr.Error); ok {
							config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, string(err.Error()))
							fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode... [Other URLs]")
							allFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
							allFileSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
						} else {
							config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, string(err.Error()))
							fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode... [Other URLs]")
							allFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
							allFileSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
						}
					}
				} else {
					fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode... [Other URLs]")
					allFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
					allFileSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
				}
			}
		} else {
			fmt.Println("Unknown platform! Switching back to scrape mode... [Other URLs]")
			allFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
			allFileSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
		}
	} else {
		allFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
		allFileSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
	}

	return allFiles, allFileSizes, nil
}

// ListS3BucketFiles lists and catalogs all files in S3 buckets
func ListS3BucketFiles(bucketURLs []string) {
	var wg sync.WaitGroup
	var scannable []string
	var notScannable []string
	var listURL types.FileListEntry
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
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return nil
				},
			}

			resp, err := client.Get(bucketURL)
			if err != nil {
				notScannable = append(notScannable, bucketURL)
				config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, bucketURL+" encountered an error during the GET request: "+err.Error())
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				notScannable = append(notScannable, bucketURL)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				notScannable = append(notScannable, bucketURL)
				return
			}

			if *config.FullScan {
				fmt.Println("Listing files using Full Mode...")
				awsHeader := resp.Header.Get("X-Amz-Bucket-Region")

				if awsHeader != "" {
					fmt.Println("\nAWS S3 Bucket detected!")
					if config.AWSCreds == "AccessKey:SecretKey" || !strings.Contains(config.AWSCreds, ":") {
						fmt.Println("Invalid S3 credentials provided! Either use the correct credentials or re-run the scan without the full mode.")
						fmt.Println("Switching back to scrape mode...")
						bucketFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
						bucketSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
					} else {
						awsBucketNameRes := config.AWSBucketNameRe.FindAllStringSubmatch(string(body), -1)
						if awsBucketNameRes != nil {
							awsBucketName := awsBucketNameRes[0][1]
							awsKeys := strings.Split(config.AWSCreds, ":")

							sess, err := session.NewSession(&aws.Config{
								Region:      aws.String(awsHeader),
								Credentials: credentials.NewStaticCredentials(awsKeys[0], awsKeys[1], ""),
							})
							if err != nil {
								fmt.Println("Failed to create session:", err)
								return
							}

							svc := s3.New(sess)

							params := &s3.ListObjectsInput{
								Bucket:  aws.String(awsBucketName),
								MaxKeys: aws.Int64(1000),
							}
							err = svc.ListObjectsPages(params, func(page *s3.ListObjectsOutput, lastPage bool) bool {
								for _, obj := range page.Contents {
									filePath := *obj.Key
									fileSize := fmt.Sprintf("%d", *obj.Size)

									bucketFiles = append(bucketFiles, []string{"", filePath})
									bucketSizes = append(bucketSizes, []string{"", fileSize})
								}
								return !lastPage
							})
							if err != nil {
								if _, ok := err.(awserr.Error); ok {
									config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, string(err.Error()))
									fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode...")
									bucketFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
									bucketSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
								} else {
									config.BucketlootOutput.Errors = append(config.BucketlootOutput.Errors, string(err.Error()))
									fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode...")
									bucketFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
									bucketSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
								}
							}
						} else {
							fmt.Println("Tool encountered an issue while scanning the bucket in Full Mode! Retrying with scrape mode...")
							bucketFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
							bucketSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
						}
					}
				} else {
					fmt.Println("Unknown platform! Switching back to scrape mode...")
					bucketFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
					bucketSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
				}
			} else {
				bucketFiles = config.BucketFileRE.FindAllStringSubmatch(string(body), -1)
				bucketSizes = config.BucketSizeRE.FindAllStringSubmatch(string(body), -1)
			}
			for i := 0; i < len(bucketFiles) && i < len(bucketSizes); i++ {
				bucketFile := bucketFiles[i]
				bucketFileSize := bucketSizes[i]
				config.IsBlacklisted = 0
				for _, blacklistExtension := range config.BlacklistExtensions {
					if strings.HasSuffix(strings.ToLower(bucketFile[1]), blacklistExtension) {
						config.IsBlacklisted = 1
						break
					}
				}
				if config.IsBlacklisted == 0 {
					if config.MaxFileSize != "" {
						buckfileSize, err := strconv.ParseInt(bucketFileSize[1], 10, 64)
						if err == nil {
							maxbucketfilesize, err := strconv.ParseInt(config.MaxFileSize, 10, 64)
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
				listURL = types.FileListEntry{URL: bucketURL, AllFiles: allFiles, IntFiles: intFiles}
				config.URLsFileList = append(config.URLsFileList, listURL)
				config.IniFileListData.ScanData = append(config.IniFileListData.ScanData, listURL)
			} else {
				if *config.DigMode {
					if !strings.HasPrefix(string(body), "<?xml") {
						fmt.Println(bucketURL, "doesn't seems to be a storage bucket! Trying to extract URLs if any from the response. [Dig Mode]")
						config.DiggedURLs = config.UniqueStrings(config.URLsRE.FindAllString(string(body), -1))
						if len(config.DiggedURLs) > 0 {
							fmt.Println("Found", len(config.DiggedURLs), "URLs in", bucketURL)
							for _, otherURL := range config.DiggedURLs {
								otherURL += "/"
								otherbucketFiles, otherBucketSizes, err := ListFilesOtherURLs(otherURL, *config.FullScan)
								if err == nil {
									if len(otherbucketFiles) > 0 {
										fmt.Printf("Discovered %v : %s\n", color.MagentaString("storage bucket with files"), otherURL)
										for i := 0; i < len(otherbucketFiles) && i < len(otherBucketSizes); i++ {
											othbucketFile := otherbucketFiles[i]
											othbucketFileSize := otherBucketSizes[i]
											config.IsBlacklisted = 0
											for _, blacklistExtension := range config.BlacklistExtensions {
												if strings.HasSuffix(strings.ToLower(othbucketFile[1]), blacklistExtension) {
													config.IsBlacklisted = 1
													break
												}
											}
											if config.IsBlacklisted == 0 {
												if config.MaxFileSize != "" {
													buckfileSize, err := strconv.ParseInt(othbucketFileSize[1], 10, 64)
													if err == nil {
														maxbucketfilesize, err := strconv.ParseInt(config.MaxFileSize, 10, 64)
														if err == nil {
															if buckfileSize <= maxbucketfilesize {
																intFiles = append(intFiles, bucketURL+othbucketFile[1])
																totalIntFiles += 1
															}
														}
													}
												} else {
													intFiles = append(intFiles, bucketURL+othbucketFile[1])
													totalIntFiles += 1
												}
											}
											allFiles = append(allFiles, otherURL+othbucketFile[1])
											totalFiles += 1
										}
										scannable = append(scannable, otherURL)
										listURL = types.FileListEntry{URL: otherURL, AllFiles: allFiles, IntFiles: intFiles}
										config.URLsFileList = append(config.URLsFileList, listURL)
										config.IniFileListData.ScanData = append(config.IniFileListData.ScanData, listURL)
									} else {
										config.Unscannable = append(config.Unscannable, bucketURL)
									}
								} else {
									config.Unscannable = append(config.Unscannable, bucketURL)
								}
							}
						} else {
							config.Unscannable = append(config.Unscannable, bucketURL)
						}
					} else {
						config.Unscannable = append(config.Unscannable, bucketURL)
					}
					if len(config.Unscannable) > 0 {
						notScannable = append(notScannable, config.UniqueStrings(config.Unscannable)...)
					}
				} else {
					notScannable = append(notScannable, bucketURL)
				}
			}
		}(bucketURL)
	}
	wg.Wait()
	config.IniFileListData.Scannable = append(config.IniFileListData.Scannable, config.UniqueStrings(scannable)...)
	config.IniFileListData.NotScannable = append(config.IniFileListData.NotScannable, config.UniqueStrings(notScannable)...)
	config.IniFileListData.TotalFiles = totalFiles
	config.IniFileListData.TotalIntFiles = totalIntFiles
}

