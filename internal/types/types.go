package types

// Rule represents a regex rule for secret detection
type Rule struct {
	Regex    string `json:"Regex"`
	Severity string `json:"Severity"`
	Title    string `json:"Title"`
}

// VulnFilesStruct represents vulnerable file patterns
type VulnFilesStruct struct {
	Name    string `json:"Name"`
	Type    string `json:"Type"`
	Match   string `json:"Match"`
	IsRegex bool   `json:"isRegex"`
}

// FileListEntry represents files from a single bucket URL
type FileListEntry struct {
	URL      string   `json:"url"`
	AllFiles []string `json:"allFiles"`
	IntFiles []string `json:"intFiles"`
}

// FileListData contains all bucket scan data
type FileListData struct {
	ScanData      []FileListEntry `json:"scanData"`
	Scannable     []string        `json:"scannable"`
	NotScannable  []string        `json:"notScannable"`
	TotalIntFiles int
	TotalFiles    int
}

// BucketlootAssetStruct represents an asset found in a bucket
type BucketlootAssetStruct struct {
	URL       string `json:"url"`
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain"`
}

// BucketlootSecretStruct represents a secret found in a bucket
type BucketlootSecretStruct struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Severity string `json:"severity"`
}

// BucketlootSensitiveFileStruct represents a sensitive file found
type BucketlootSensitiveFileStruct struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// BucketlootKeywordStruct represents a keyword match
type BucketlootKeywordStruct struct {
	URL     string `json:"url"`
	Keyword string `json:"keyword"`
	Type    string `json:"type"`
}

// BucketLootResStruct represents scan results for a single bucket
type BucketLootResStruct struct {
	BucketUrl string `json:"bucketUrl"`
	Assets    []struct {
		URL       string `json:"url"`
		Domain    string `json:"domain"`
		Subdomain string `json:"subdomain"`
	} `json:"Assets"`
	Secrets []struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Severity string `json:"severity"`
	} `json:"Secrets"`
	SensitiveFiles []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"SensitiveFiles"`
	Keywords []struct {
		URL     string `json:"url"`
		Keyword string `json:"keyword"`
		Type    string `json:"type"`
	} `json:"Keywords,omitempty"`
}

// BucketLootOpStruct represents the complete output
type BucketLootOpStruct struct {
	Results []struct {
		BucketUrl string `json:"bucketUrl"`
		Assets    []struct {
			URL       string `json:"url"`
			Domain    string `json:"domain"`
			Subdomain string `json:"subdomain"`
		} `json:"Assets"`
		Secrets []struct {
			Name     string `json:"name"`
			URL      string `json:"url"`
			Severity string `json:"severity"`
		} `json:"Secrets"`
		SensitiveFiles []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"SensitiveFiles"`
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

// PlatformCreds represents credentials for different platforms
type PlatformCreds []struct {
	Platform    string `json:"platform"`
	Credentials string `json:"credentials"`
}

// NotifyConf represents notification configuration
type NotifyConf struct {
	Discord string `json:"Discord"`
	Slack   string `json:"Slack"`
}

