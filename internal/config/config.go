package config

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/redhuntlabs/bucketloot/internal/types"
)

//go:embed data/blacklist.txt
var blacklistData string

//go:embed data/regexes.json
var regexesData []byte

//go:embed data/vulnFiles.json
var vulnFilesData []byte

// Global variables
var (
	Args                 []string
	AllURLs              []string
	BlacklistExtensions  []string
	IsBlacklisted        int
	DiggedURLs           []string
	URLAssets            []string
	DomAssets            []string
	Unscannable          []string
	SubAssets            []string
	SlowScan             *bool
	DigMode              *bool
	Notify               *bool
	ErrorLogging         *bool
	FullScan             *bool
	ScanKeywords         []string
	URLsFileList         []types.FileListEntry
	IniFileListData      types.FileListData
	VulnerableFileChecks []types.VulnFilesStruct
	MaxFileSize          string
	KeywordSearch        string
	SaveOutput           string
	AWSCreds             string
	BucketlootOutput     types.BucketLootOpStruct
	Rules                []types.Rule
	Platforms            []types.NotifyConf
)

// Regex patterns
var (
	BucketFileRE    = regexp.MustCompile(`(?m)(?i)<key>(.+?)<\/key>`)
	BucketSizeRE    = regexp.MustCompile(`(?i)<Size>(.+?)<\/Size>`)
	URLRE           = regexp.MustCompile(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
	URLValidation   = regexp.MustCompile(`^(?:(?:https?|ftp):\/\/)?(?:www\.)?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(?:\/[^\s]*)?$`)
	URLsRE          = regexp.MustCompile(`(http[s]?:\/\/[^\s\/]+)\b`)
	AWSBucketNameRe = regexp.MustCompile(`<Name>(.+?)<\/Name>`)
)

const Banner = `
,.--'''''''''--.,  ____             _        _   _                 _   
(\'-.,_____,.-'/) |  _ \           | |      | | | |               | |  
 \\-.,_____,.-//  | |_) |_   _  ___| | _____| |_| |     ___   ___ | |_ 
 ;\\         //|  |  _ <| | | |/ __| |/ / _ \ __| |    / _ \ / _ \| __|
 | \\  ___  // |  | |_) | |_| | (__|   <  __/ |_| |___| (_) | (_) | |_ 
 |  '-[___]-'  |  |____/ \__,_|\___|_|\_\___|\__|______\___/ \___/ \__|
 |             |                                                       
 |             |  An Automated S3 Bucket Inspector                                             
 |             |  Developed by Umair Nehri (@umair9747)            
 ''-.,_____,.-''                                                        
`

// Initialize loads all configuration data
func Initialize() error {
	BucketlootOutput.Version = "2.0"

	// Read the blacklist extensions from embedded data
	scanner := bufio.NewScanner(strings.NewReader(blacklistData))
	for scanner.Scan() {
		BlacklistExtensions = append(BlacklistExtensions, scanner.Text())
	}

	// Read the regex JSON from embedded data
	if err := json.Unmarshal(regexesData, &Rules); err != nil {
		return fmt.Errorf("error decoding regexes JSON: %v", err)
	}

	// Read the vulnFiles JSON from embedded data
	if err := json.Unmarshal(vulnFilesData, &VulnerableFileChecks); err != nil {
		return fmt.Errorf("error unmarshaling vulnFiles JSON: %v", err)
	}

	return nil
}

// UniqueStrings returns unique strings from input slice
func UniqueStrings(input []string) []string {
	uniqueMap := make(map[string]bool)
	uniqueEntries := []string{}

	for _, str := range input {
		if !uniqueMap[str] {
			uniqueEntries = append(uniqueEntries, str)
			uniqueMap[str] = true
		}
	}

	return uniqueEntries
}

// ReadCredsFile reads AWS credentials from credentials.json
func ReadCredsFile() {
	file, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatalln("Error reading credentials.json file, Exiting! \n", err)
		return
	}
	var data types.PlatformCreds
	err = json.Unmarshal(file, &data)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	for _, entry := range data {
		if entry.Platform == "AWS" {
			AWSCreds = entry.Credentials
		}
	}
}

// LoadNotifyConfig loads notification configuration
func LoadNotifyConfig() error {
	fileContent, err := os.ReadFile("notifyConfig.json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileContent, &Platforms)
	if err != nil {
		return err
	}
	return nil
}
