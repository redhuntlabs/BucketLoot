package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/fatih/color"
	tld "github.com/jpillora/go-tld"
)

var tempDir = ".temp"
var tempFileSuffix = "temp_s3_file_"

func scanS3FilesSlow(fileURLs []string, bucketURL string) error {
	var errors []error

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

		// Make HTTP request to S3 bucket URL
		resp, err := http.Get(fileURL)
		if err != nil {
			errors = append(errors, fmt.Errorf("error making HTTP request to S3 bucket file URL: %v", err))
			continue
		}
		defer resp.Body.Close()

		// Check response status code for errors
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

		// Read response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			errors = append(errors, fmt.Errorf("error reading response body from S3 bucket file URL: %v: %s", err, fileURL))
			continue
		}

		// Parse HTML to scan S3 Files
		//Extract Secrets
		for regName, regValue := range regexList {
			reg := regexp.MustCompile(regValue)
			if reg.MatchString(string(body)) {
				fmt.Printf("Discovered %v in %s\n", color.RedString("SECRET["+regName+"]"), fileURL)
				bucketLootSecret.Name = regName
				bucketLootSecret.URL = fileURL
				bucketScanRes.Secrets = append(bucketScanRes.Secrets, bucketLootSecret)
				bucketLootSecret.Name = ""
				bucketLootSecret.URL = ""
			}
		}

		//LOOK FOR POTENTIALLY SENSITIVE/VULN FILES
		for _, check := range vulnerableFileChecks {
			// Compile the regex pattern
			var re *regexp.Regexp
			re, err = regexp.Compile(check.Match)
			if err != nil {
				errors = append(errors, fmt.Errorf("Error compiling vuln files regex %s", err))
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
	var mu sync.Mutex
	var errors []error

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

			var (
				bucketLootAsset   bucketlootAssetStruct
				bucketLootSecret  bucketlootSecretStruct
				bucketLootKeyword bucketlootKeywordStruct
				bucketLootFile    bucketlootSensitiveFileStruct
				keywordDisc       int
			)

			resp, err := http.Get(url)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("error making HTTP request to S3 bucket file URL: %v", err))
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				mu.Lock()
				if resp.StatusCode == http.StatusNotFound {
					errors = append(errors, fmt.Errorf("s3 bucket file not found: %s", url))
				} else if resp.StatusCode == http.StatusForbidden {
					errors = append(errors, fmt.Errorf("s3 bucket file is private: %s", url))
				} else {
					errors = append(errors, fmt.Errorf("unexpected response status code from S3 bucket file URL: %d: %s", resp.StatusCode, url))
				}
				mu.Unlock()
				return
			}

			// Create a temporary file in the custom directory to store the downloaded content
			tempFile, err := ioutil.TempFile(tempDir, tempFileSuffix)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("error creating temporary file: %v", err))
				mu.Unlock()
				return
			}
			defer tempFile.Close()

			// Copy the response body to the temporary file
			_, err = io.Copy(tempFile, resp.Body)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("error copying response body to temporary file: %v", err))
				mu.Unlock()
				return
			}

			// Read the content from the temporary file
			body, err := ioutil.ReadFile(tempFile.Name())
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("error reading content from the temporary file: %v", err))
				mu.Unlock()
				return
			}

			for regName, regValue := range regexList {
				reg := regexp.MustCompile(regValue)
				if reg.MatchString(string(body)) {
					fmt.Printf("Discovered %v in %s\n", color.RedString("SECRET["+regName+"]"), url)
					bucketLootSecret.Name = regName
					bucketLootSecret.URL = url
					mu.Lock()
					bucketScanRes.Secrets = append(bucketScanRes.Secrets, bucketLootSecret)
					mu.Unlock()
					bucketLootSecret.Name = ""
					bucketLootSecret.URL = ""
				}
			}

			//LOOK FOR POTENTIALLY SENSITIVE/VULN FILES
			for _, check := range vulnerableFileChecks {
				// Compile the regex pattern
				var re *regexp.Regexp
				re, err = regexp.Compile(check.Match)
				if err != nil {
					errors = append(errors, fmt.Errorf("Error compiling vuln files regex %s", err))
					continue
				}

				// Check if the pattern matches the fileURL
				if re != nil {
					if re.MatchString(url) {
						fmt.Printf("Discovered %v in %s\n", color.YellowString("POTENTIALLY SENSITIVE FILE["+check.Name+"]"), url)
						bucketLootFile.Name = check.Name
						bucketLootFile.URL = url
						mu.Lock()
						bucketScanRes.SensitiveFiles = append(bucketScanRes.SensitiveFiles, bucketLootFile)
						mu.Unlock()
						bucketLootFile.Name = ""
						bucketLootFile.URL = ""
					}
				}
			}

			extURLs := urlRE.FindAllString(string(body), -1)
			mu.Lock()
			urlAssets = append(urlAssets, extURLs...)
			mu.Unlock()
			if len(extURLs) > 0 {
				fmt.Printf("Discovered %v in %s\n", color.BlueString("URL(s)"), url)
			}

			for _, u := range extURLs {
				bucketLootAsset.URL = u
				asset, err := tld.Parse(u)
				if err == nil {
					mu.Lock()
					domAssets = append(domAssets, asset.Domain+"."+asset.TLD)
					bucketLootAsset.Domain = asset.Domain + "." + asset.TLD
					if asset.Subdomain != "" {
						subAssets = append(subAssets, asset.Subdomain+"."+asset.Domain+"."+asset.TLD)
						bucketLootAsset.Subdomain = asset.Subdomain + "." + asset.Domain + "." + asset.TLD
					}
					mu.Unlock()
				}
				mu.Lock()
				bucketScanRes.Assets = append(bucketScanRes.Assets, bucketLootAsset)
				mu.Unlock()
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
					mu.Lock()
					bucketScanRes.Keywords = append(bucketScanRes.Keywords, bucketLootKeyword)
					keywordDisc = 1
					mu.Unlock()
				}
				if keywordRe.MatchString(string(body)) {
					bucketLootKeyword.Keyword = keyword
					bucketLootKeyword.URL = url
					bucketLootKeyword.Type = "FileContent"
					mu.Lock()
					bucketScanRes.Keywords = append(bucketScanRes.Keywords, bucketLootKeyword)
					keywordDisc = 1
					mu.Unlock()
				}
			}

			if keywordDisc == 1 {
				fmt.Printf("Discovered %v in %s\n", color.GreenString("Keyword(s)"), url)
			}

			os.RemoveAll(tempDir)

		}(fileURL)
	}

	wg.Wait()

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
