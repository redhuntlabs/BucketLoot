package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/redhuntlabs/bucketloot/internal/config"
)

// FormatURL adds http:// prefix and trailing slash to URLs
func FormatURL(urls []string) []string {
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

// ReadFile reads URLs from a file
func ReadFile(fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.ReplaceAll(scanner.Text(), " ", "")
		if config.URLValidation.MatchString(url) {
			config.AllURLs = append(config.AllURLs, url)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
	}
}

// ToJSON marshals and outputs the results
func ToJSON() {
	jsonData, err := json.MarshalIndent(config.BucketlootOutput, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	fmt.Println("\n" + string(jsonData))
	if config.SaveOutput != "" {
		file, err := os.Create(config.SaveOutput)
		if err != nil {
			fmt.Println("Error creating file:", err)
			return
		}
		defer file.Close()

		_, err = file.Write(jsonData)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
		fmt.Println("Data successfully saved to", config.SaveOutput)
	}
}

// NotifyDiscord sends notification to Discord webhook
func NotifyDiscord(webhookURL, message string) error {
	jsonData := fmt.Sprintf(`{"content":"%s"}`, message)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBufferString(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// NotifySlack sends notification to Slack webhook
func NotifySlack(webhookURL, message string) error {
	jsonData := fmt.Sprintf(`{"text":"%s"}`, message)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBufferString(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}
