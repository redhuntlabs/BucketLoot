package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/fatih/color"
	tld "github.com/jpillora/go-tld"
)

var tempDir = ".temp"
var tempFileSuffix = "temp_s3_file_"

func scanS3FilesSlow(fileURLs []string, bucketURL string) error {
	var errors []error

	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}

	//BELOW CODE BLOCK IS FOR ARRANGING BUCKETLOOT OUTPUT
	var bucketScanRes bucketLootResStruct
	bucketScanRes.BucketUrl = bucketURL

	for _, fileURL := range fileURLs {
		var (
			bucketLootAsset   bucketlootAssetStruct
			bucketLootSecret  bucketlootSecretStruct
			bucketLootFile    bucketlootSensitiveFileStruct
			bucketLootKeyword bucketlootKeywordStruct
			keywordDisc       int
		)

		// Create a temporary file in the custom directory to store the downloaded content
		tempFile, err := ioutil.TempFile(tempDir, tempFileSuffix)
		if err != nil {
			errors = append(errors, fmt.Errorf("error creating temporary file: %v", err))
			continue
		}
		defer tempFile.Close()

		// Make HTTP request to S3 bucket
		resp, err := http.Get(fileURL)

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

		body, err := ioutil.ReadFile(tempFile.Name())
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

		//Extract SecretsName
		for regName, regValue := range regexList {
			reg := regexp.MustCompile(regValue)

			if reg.MatchString(string(body)) {
				fmt.Printf("Discovered %v in %s\n", color.RedString("SECRET["+rule.Title+"]"), fileURL)
				bucketLootSecret.Name = rule.Title
				bucketLootSecret.URL = fileURL
				bucketLootSecret.Severity = rule.Severity
				bucketScanRes.Secrets = append(bucketScanRes.Secrets, bucketLootSecret)
				bucketLootSecret.Name = ""
				bucketLootSecret.URL = ""

				if *notify {
					if platforms[0].Discord != "" {
						err := notifyDiscord(platforms[0].Discord, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+fileURL+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
						if err != nil {
							if strings.Contains(err.Error(), "204") {
								fmt.Println("Notified successfully!")
							} else {
								fmt.Println("Couldn't notify!")
							}
							errors = append(errors, fmt.Errorf("error notifying! %s", err))
						}
					}
					if platforms[1].Slack != "" {
						err := notifySlack(platforms[1].Slack, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+fileURL+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
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

		//LOOK FOR POTENTIALLY SENSITIVE/VULN FILES
		for _, check := range vulnerableFileChecks {
			// Compile the regex pattern
			var re *regexp.Regexp
			re, err = regexp.Compile(check.Match)
			if err != nil {
				errors = append(errors, fmt.Errorf("error compiling vuln files regex %s", err))
				continue
			}

			// Check if the pattern matches the fileURL
			if re != nil {
				if re.MatchString(fileURL) {
					fmt.Printf("Discovered %v in %s\n", color.YellowString("POTENTIALLY SENSITIVE FILE["+check.Name+"]"), fileURL)
					bucketLootFile.Name = check.Name
					bucketLootFile.URL = fileURL
					bucketScanRes.SensitiveFiles = append(bucketScanRes.SensitiveFiles, bucketLootFile)
					bucketLootFile.Name = ""
					bucketLootFile.URL = ""

					if *notify {
						if platforms[0].Discord != "" {
							err := notifyDiscord(platforms[0].Discord, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+fileURL+" | BUCKET URL: "+bucketURL)
							if err != nil {
								if strings.Contains(err.Error(), "204") {
									fmt.Println("Notified successfully!")
								} else {
									fmt.Println("Couldn't notify!")
								}
								errors = append(errors, fmt.Errorf("error notifying! %s", err))
							}
						}
						if platforms[1].Slack != "" {
							err := notifySlack(platforms[1].Slack, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+fileURL+" | BUCKET URL: "+bucketURL)
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

		//Extract URLs
		extURLs := urlRE.FindAllString(string(body), -1) // EXTRACT URLS FROM FILE
		urlAssets = append(urlAssets, extURLs...)        // APPEND TO ENTIRE URL LIST
		if len(extURLs) > 0 {
			fmt.Printf("Discovered %v in %s\n", color.BlueString("URL(s)"), fileURL)
		}

		//Extract Domains - Subdomains
		for _, u := range extURLs { // USE URLS EXTRACTED FROM FILE FOR SCANNING
			bucketLootAsset.URL = u
			asset, err := tld.Parse(u)
			if err == nil {
				domAssets = append(domAssets, asset.Domain+"."+asset.TLD) // APPEND TO ENTIRE DOMAIN LIST
				bucketLootAsset.Domain = asset.Domain + "." + asset.TLD
				if asset.Subdomain != "" { // IF THE ASSET URL HAS A SUBDOMAIN
					subAssets = append(subAssets, asset.Subdomain+"."+asset.Domain+"."+asset.TLD) // APPEND TO ENTIRE DOMAIN LIST
					bucketLootAsset.Subdomain = asset.Subdomain + "." + asset.Domain + "." + asset.TLD
				}
			}
			bucketScanRes.Assets = append(bucketScanRes.Assets, bucketLootAsset)
			bucketLootAsset.URL = ""
			bucketLootAsset.Domain = ""
			bucketLootAsset.Subdomain = ""
		}

		// SEARCH FOR USER DEFINED KEYWORDS
		for _, keyword := range scanKeywords {
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

	bucketlootOutput.Results = append(bucketlootOutput.Results, bucketScanRes)
	if len(errors) > 0 {
		for _, err := range errors {
			if *errorLogging {
				bucketlootOutput.Errors = append(bucketlootOutput.Errors, string(err.Error()))
			}
		}
	}

	return nil
}

func scanS3FilesFast(fileURLs []string, bucketURL string) error {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var errors []error
	var downloadedFiles []string

	var (
		bucketLootAsset   bucketlootAssetStruct
		bucketLootSecret  bucketlootSecretStruct
		bucketLootKeyword bucketlootKeywordStruct
		bucketLootFile    bucketlootSensitiveFileStruct
		keywordDisc       int
	)

	os.RemoveAll(tempDir)

	// Create a temporary directory in the current working directory
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}

	bucketScanRes := bucketLootResStruct{
		BucketUrl: bucketURL,
	}

	for _, fileURL := range fileURLs {
		wg.Add(1)

		go func(url string) {
			defer wg.Done()

			resp, err := http.Get(url)

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

			// Create a temporary file in the custom directory to store the downloaded content
			tempFile, err := ioutil.TempFile(tempDir, tempFileSuffix)
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

			// writes the source URL of the file to the end of the file
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

			body, err := ioutil.ReadFile(filePath)
			lines := strings.Split(string(body), "\n")
			urlByte, err := base64.StdEncoding.DecodeString(lines[len(lines)-1])
			url := string(urlByte)

			if err != nil {
				mutex.Lock()
				errors = append(errors, fmt.Errorf("error reading content from the temporary file: %v", err))
				mutex.Unlock()
				return
			}
			for _, rule := range rules {
				reg := regexp.MustCompile(rule.Regex)
				if reg.MatchString(string(body)) {
					fmt.Printf("Discovered %v in %s\n", color.RedString("SECRET["+rule.Title+"]"), url)
					bucketLootSecret.Name = rule.Title
					bucketLootSecret.URL = url
          
					mutex.Lock()

					bucketScanRes.Secrets = append(bucketScanRes.Secrets, bucketLootSecret)
					mutex.Unlock()
					bucketLootSecret.Name = ""
					bucketLootSecret.URL = ""

					if *notify {
						if platforms[0].Discord != "" {
							err := notifyDiscord(platforms[0].Discord, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+url+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
							if err != nil {
								if strings.Contains(err.Error(), "204") {
									fmt.Println("Notified successfully! [DISCORD]")
								} else {
									fmt.Println("Couldn't notify! [DISCORD]")
								}
								errors = append(errors, fmt.Errorf("error notifying! %s", err))
							}
						}
						if platforms[1].Slack != "" {
							err := notifySlack(platforms[1].Slack, "BucketLoot discovered a secret! | SECRET TYPE: "+rule.Title+" | SECRET URL: "+url+" | SECRET SEVERITY: "+rule.Severity+" | BUCKET URL: "+bucketURL)
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
			//LOOK FOR POTENTIALLY SENSITIVE/VULN FILES
			for _, check := range vulnerableFileChecks {
				// Compile the regex pattern
				var re *regexp.Regexp
				re, err = regexp.Compile(check.Match)
				if err != nil {
					errors = append(errors, fmt.Errorf("error compiling vuln files regex %s", err))
					continue
				}

				// Check if the pattern matches the fileURL
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

						if *notify {
							if platforms[0].Discord != "" {
								err := notifyDiscord(platforms[0].Discord, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+url+" | BUCKET URL: "+bucketURL)
								if err != nil {
									if strings.Contains(err.Error(), "204") {
										fmt.Println("Notified successfully! [DISCORD]")
									} else {
										fmt.Println("Couldn't notify! [DISCORD]")
									}
									errors = append(errors, fmt.Errorf("error notifying! %s", err))
								}
							}
							if platforms[1].Slack != "" {
								err := notifySlack(platforms[1].Slack, "BucketLoot discovered a potentially sensitive file! | INFO: "+check.Name+" | FILE URL: "+url+" | BUCKET URL: "+bucketURL)
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

			extURLs := urlRE.FindAllString(string(body), -1)
			mutex.Lock()
			urlAssets = append(urlAssets, extURLs...)
			mutex.Unlock()
			if len(extURLs) > 0 {
				fmt.Printf("Discovered %v in %s\n", color.BlueString("URL(s)"), url)
			}

			for _, u := range extURLs {
				bucketLootAsset.URL = u
				asset, err := tld.Parse(u)
				if err == nil {
					mutex.Lock()
					domAssets = append(domAssets, asset.Domain+"."+asset.TLD)
					bucketLootAsset.Domain = asset.Domain + "." + asset.TLD
					if asset.Subdomain != "" {
						subAssets = append(subAssets, asset.Subdomain+"."+asset.Domain+"."+asset.TLD)
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

			for _, keyword := range scanKeywords {
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

	bucketlootOutput.Results = append(bucketlootOutput.Results, bucketScanRes)
	if len(errors) > 0 {
		for _, err := range errors {
			if *errorLogging {
				bucketlootOutput.Errors = append(bucketlootOutput.Errors, string(err.Error()))
			}
		}
	}

	return nil
}
