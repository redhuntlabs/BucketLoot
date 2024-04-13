package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

func processGrayhat() ([]string, error) {
	if ghwCreds == "API-Key" {
		log.Println("Looks like you are yet to replace the dummy string in credentials.json! Skipping the Grayhatwarfare module...")
		return nil, nil
	}
	var result []string
	for _, grayhatwfKeyword := range grayhatwfKeywords {
		url := "https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=" + grayhatwfKeyword + "&order=fileCount&direction=desc&limit=1000"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Error creating request: %v", err)
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+ghwCreds)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error sending request: %v", err)
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Received non-200 status code: %d", resp.StatusCode)
			return nil, nil
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body: %v", err)
			return nil, err
		}

		var data grayhatwfstruct
		if err := json.Unmarshal(body, &data); err != nil {
			log.Printf("Error decoding JSON: %v", err)
			return nil, err
		}

		uniqueBuckets := make(map[string]bool)
		for _, bucket := range data.Buckets {
			uniqueBuckets[bucket.Bucket] = true
		}

		for bucket := range uniqueBuckets {
			result = append(result, bucket)
		}
	}
	return result, nil
}
