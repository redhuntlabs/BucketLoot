package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
)

var args []string
var allURLs []string
var bucketFileRE = regexp.MustCompile(`(?m)(?i)<key>(.+?)<\/key>`)
var bucketSizeRE = regexp.MustCompile(`(?i)<Size>(.+?)<\/Size>`)
var urlRE = regexp.MustCompile(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
var urlValidation = regexp.MustCompile(`^(?:(?:https?|ftp):\/\/)?(?:www\.)?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(?:\/[^\s]*)?$`)
var blacklistExtensions []string
var isBlacklisted int
var regexList map[string]string
var urlAssets []string
var domAssets []string
var subAssets []string
var slowScan *bool
var errorLogging *bool
var fullScan *bool
var scanKeywords []string

var urlsFileList []fileListEntry
var iniFileListData fileListData

var vulnerableFileChecks []vulnFilesStruct

var maxFileSize string
var keywordSearch string
var saveOutput string

var awsCreds string
var awsBucketNameRe = regexp.MustCompile(`<Name>(.+?)<\/Name>`)

//VAR DECLARATION FOR BUCKETLOOT OUTPUT

var bucketlootOutput bucketLootOpStruct

//BELOW IS THE STRUCTURE FOR PARSING THE VULNFILES JSON FILE
type vulnFilesStruct struct {
	Name    string `json:"Name"`
	Type    string `json:"Type"`
	Match   string `json:"Match"`
	IsRegex bool   `json:"isRegex"`
}

//BELOW STRUCT ARE RELATED TO URLS WHOSE FILES ARE EXTRACTED.
//First struct is for a single entry of ScanData array. It stores all the scannable bucket entries
// Allfiles - all the files that are present in the bucket, irrespective of extension
// Intfiles - all interesting files that are to be scanned
// Second struct stores the array of first struct as well as 2 other arrays, scannable and notscannable which shows how many urls from input
// can be scanned and how many are ignored because of errors during requests, private buckets, error during deserialisation etc.

type fileListEntry struct {
	URL      string   `json:"url"`
	AllFiles []string `json:"allFiles"`
	IntFiles []string `json:"intFiles"`
}
type fileListData struct {
	ScanData      []fileListEntry `json:"scanData"`
	Scannable     []string        `json:"scannable"`
	NotScannable  []string        `json:"notScannable"`
	TotalIntFiles int
	TotalFiles    int
}

//BELOW ARE THE STRUCTS FOR BUCKETLOOT OUTPUT
//FIRST ONE IS THE STRUCT FORMAT FOR A SINGLE BUCKET SCAN RESULT
//SECOND IS THE OUTPUT FORMAT THAT BUCKETLOOT RETURNS IN TOTAL

type bucketlootAssetStruct struct {
	URL       string `json:"url"`
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain"`
}

type bucketlootSecretStruct struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type bucketlootSensitiveFileStruct struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type bucketlootKeywordStruct struct {
	URL     string `json:"url"`
	Keyword string `json:"keyword"`
	Type    string `json:"type"`
}

type bucketLootResStruct struct {
	BucketUrl string `json:"bucketUrl"`
	Assets    []struct {
		URL       string `json:"url"`
		Domain    string `json:"domain"`
		Subdomain string `json:"subdomain"`
	} `json:"Assets"`
	Secrets []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"Secrets"`
	SensitiveFiles []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"SensitiveFiles,omitempty"`
	Keywords []struct {
		URL     string `json:"url"`
		Keyword string `json:"keyword"`
		Type    string `json:"type"`
	} `json:"Keywords,omitempty"`
}
type bucketLootOpStruct struct {
	Results []struct {
		BucketUrl string `json:"bucketUrl"`
		Assets    []struct {
			URL       string `json:"url"`
			Domain    string `json:"domain"`
			Subdomain string `json:"subdomain"`
		} `json:"Assets"`
		Secrets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"Secrets"`
		SensitiveFiles []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"SensitiveFiles,omitempty"`
		Keywords []struct {
			URL     string `json:"url"`
			Keyword string `json:"keyword"`
			Type    string `json:"type"`
		} `json:"Keywords,omitempty"`
	} `json:"Results"`
	Version string   `json:"version"`
	Scanned []string `json:"Scanned"`
	Skipped []string `json:"Skipped"`
	Errors  []string `json:"Errors,omitempty"`
}

// STRUCT FOR DECODING CREDENTIALS.JSON
type platformCreds []struct {
	Platform    string `json:"platform"`
	Credentials string `json:"credentials"`
}

func init() {

	bucketlootOutput.Version = "2.0"

	//READ THE BLACKLIST EXTENSIONS FILE
	file, err := os.Open("blacklist.txt")
	if err != nil {
		log.Fatalln("[Error] Looks like the tool is facing some issue while loading the specified file. [", err.Error(), "]")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		blacklistExtensions = append(blacklistExtensions, scanner.Text())
	}

	//READ THE REGEX JSON FILE AND PARSE IT
	regexJSON, err := ioutil.ReadFile("regexes.json")
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal((regexJSON), &regexList); err != nil {
		fmt.Println(err)
		return
	}

	//READ THE VULNFILES JSON FILE AND PARSE IT
	// Read the JSON file into a byte slice
	data, err := ioutil.ReadFile("vulnFiles.json")
	if err != nil {
		fmt.Println("Error reading the JSON file:", err)
		return
	}

	// Unmarshal the JSON data into the extensions slice
	err = json.Unmarshal(data, &vulnerableFileChecks)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

}

const banner = `
,.--'''''''''--.,  ____             _        _   _                 _   
(\'-.,_____,.-'/) |  _ \           | |      | | | |               | |  
 \\-.,_____,.-//  | |_) |_   _  ___| | _____| |_| |     ___   ___ | |_ 
 ;\\         //|  |  _ <| | | |/ __| |/ / _ \ __| |    / _ \ / _ \| __|
 | \\  ___  // |  | |_) | |_| | (__|   <  __/ |_| |___| (_) | (_) | |_ 
 |  '-[___]-'  |  |____/ \__,_|\___|_|\_\___|\__|______\___/ \___/ \__|
 |             |                                                       
 |             |  An Automated S3 Bucket Inspector                                             
 |             |  Developed by Umair Nehri (@umair9747) and Owais Shaikh (@4f77616973)             
 ''-.,_____,.-''                                                        
`
