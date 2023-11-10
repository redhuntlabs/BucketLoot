<h1>Documentation</h1>
<hr style="height: 1px;">
<div id="setup">
<h2> Setup </h2>
<h3>1. Tool Setup</h3>
The tool is written in Go, so make sure to <a href="https://go.dev/dl/">install</a> it on your system before proceeding. The setup is pretty easy and straight forward. Just follow the below steps in order to quickly install and get the binary working.
<br>
<br>
Firstly clone the repo to any directory/path of your liking,<br><br>

```
git clone https://github.com/redhuntlabs/BucketLoot.git
```
Afer this, just run the following command in order to build the binary according to your environment.

```
go build
```

<h3>2. Credentials Setup (Optional) </h3>
In order to setup the tool for the full scan mode (optional), you need to modify the <a href="../credentials.json">credentials.json</a> file and add the credentials for the target platforms for whom you would like to run a full scan against. At the moment, BucketLoot only supports AWS for running full mode scans, and we expect the release of another one or two modules for other platforms very soon.
<h4><u>AWS</u></h4>

In order to run the AWS module for the full scan mode, you need to generate the Access Key and Secret Key from the <a href="https://console.aws.amazon.com/iamv2/">IAM Dashboard</a> by heading to the <b>users</b> section, clicking on any user you would like to use for the tool, going to the <b>Security Credentials</b> tab, clicking on the <b>create access key</b> button, choosing "Third-party service" and finally creating the accees key.

Make sure that the user has the "<b>AmazonS3FullAccess</b>" permission policy attached, since its absence may lead to errors and issues with the scan.

<h3>3. Webhook Notification Setup (OPtional)</h3>
In order to utilise the webhook notification feature of BucketLoot, you are supposed to modify the <a href="../notifyConfig.json">notifyConfig.json</a> file. This file allows you to provide the webhook URLs for Slack and Discord channels where you would like to post the notifications. [Note: It is not manadatory to provide the webhook URLs for both the platforms at once.]<br>
Users are recommended to check the below resources to understand how they can create the webhook URLs for the same:
<ul type="disc">
  <li><b>Discord:<b> <a href="https://hookdeck.com/webhooks/platforms/how-to-get-started-with-discord-webhooks#conclusion">here</a></li>
  <li><b>Slack:</b> <a href="https://sankalpit.com/plugins/documentation/how-to-create-slack-incoming-webhook-url/">here</a></li>
</ul>
</div>
<hr style="height: 1px;">
<div id="usage">
<h2> Usage </h2>

<h4>1. Basic Scan </h4>
In order to run a basic scan without any extra flags, you just need to provide a target URL or target(s) file as an argument.<br><br>

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/

                    OR

umair@redhuntlabs:~/bucketloot$ ./bucketloot targets.txt
```

<h4>2. Additional Flags </h4>

BucketLoot also offers several additional flags that can help customise your scan and get the right results that you need.

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot -H
flag provided but not defined: -H
Usage of ./bucketloot:
  -dig
        Extract and scan buckets from all targets that are not storage buckets!
  -full
        Go beyond the 1000 file scan limit [Requires additional setup!]
  -log-errors
        Log errors in final output
  -max-size string
        Maximum file size (in bytes)
  -notify
        Notify using webhooks whenever the tool finds security exposure
  -save string
        Save tool output, should either end with .txt or .json [Default output file name is output.json]
  -search string
        Keyword(s) to look for during the scan. [Possible values -> keyword, keyword1:::keyword2, keywords.txt]
  -slow
        Set slow mode for the scan
```
<h5>-dig</h5>
Go beyond storage buckets as input and let BucketLoot scan all targets irrespective of whether they are buckets or not. The tool determine if the target endpoint is a non-bucket URL and if it is, it would scrape all URLs from it, look for any valid and misconfigured buckets and scan them like it always does! [Note: By using this flag its not necessary that you only have to provide non-storage bucket targets.]

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -dig
```

<h5>-full</h5>

If you would like to go beyond the maximum 1000 files per bucket limit, you can run BucketLoot's Full scan mode by <a href="#setup">setting up the target platform's access credentials</a>. Currently we only support full scan mode for Amazon Web Services and expect to release the modules for other platforms very soon.
If for some reason, during the full scan, the tool encounters any authentication or permission issue, it will automatically switch back to scraping mode for that individual bucket.

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -full
```

<h5>-log-errors</h5>

BucketLoot allows users to save all the errors it encountered during the scan within the tool output. This can be helpful especially during the debugging process and can even help us to understand the reported issues better. The flag creates an additional array named Errors within the JSON output. 

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -log-errors
```

<h5>-max-size</h5>

Often users can encounter buckets that contain huge files. This can add up to the scan completion time and might not be an ideal scenario for systems with less bandwidth. The -max-size flag allows users to provide the maximum file size which they would like to scan for (in bytes).

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -max-size 13521
```

<h5>-notify</h5>

Get notified on the go whenever the tool discovers any security exposure. Connect BucketLoot to Discord or Slack using webhooks and let the magic unfold!<br>
For this flag, it is required for you to setup the <a href="../notifyConfig.json">notifyConfig.json</a> file. Refer to the Setup section for more details.

<h5>-save</h5

Saves the JSON output that your tool generates for users to go through or parse for further processing. The tool saves the output in a file named <b>output.json</b> by default if the flag is provided. User has the ability to provide custom output file names, either in .txt or .json format.

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -save

                                    OR
                                
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -save myscan.json
```

<h5>-search</h5>

Users can use the -search flag in order to query for specific keywords or regular expressions within the file contents from an exposed storage bucket. There are several ways through which the keywords can be passed to the tool.

1. Search an individual keyword/RegEx query

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -search 'admin'
```
2. Search for multiple keywords/RegEx queries (using ::: as a separator)
```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -search 'admin:::login:::password:::API:::.*dev-instance'
```
3. Search for multiple keywords/RegEx queries (using a .txt file containing the list)
```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -search queries.txt
```

<h5>-slow</h5>

Designed for systems with low network bandwidth where the consistency of results is important, the -slow flag allows to run all the scans sequentially instead of concurrently [Fast mode] which is the default behavious of the tool. Although this would definitely increase the overall scan time, the tool will provide consistent results while also making sure that it can run hassle-free locally.

```
umair@redhuntlabs:~/bucketloot$ ./bucketloot https://myvulninstance.s3.amazonaws.com/ -slow
```
</div>

<hr style="height: 1px;">

<h4>3. Output </h4>

BucketLoot returns a JSON output at the end of every scan. The tool has the following structure:

```
type bucketLootOpStruct struct {
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
```

The Keywords and Errors array only show up when their respective flags are provided as an input and thus omitted if empty.
Here, Results is an array storing the scan data for every individual misconfigured bucket that was scanned and from whom results were derivedd. The unique identifier here is the BucketURL field. Outside of the array we have the version field containing the tool version, Scanned is an array showing the URLs that successfully got scanned, Skipped stores all the URLs which werne't scanned either because they were not valid S3 endpoints, were private or had some issue while making a request. The errors array (optional) stores all the errors caught during the scan as raw strings.

Here's an example output for a basic scan to give you a glimpse of how the tool works,

```
➜  bucketloot git:(master) ✗  ./bucketloot https://bucketloot-testing.blr1.digitaloceanspaces.com/

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
 

 
Processing arguments...

 
Discovered a total of 6 bucket files...
Total bucket files of interest: 6

 
Starting to scan the files... [FAST]
Discovered SECRET[AWS Access Key ID] in https://bucketloot-testing.blr1.digitaloceanspaces.com/credentials.json
Discovered URL(s) in https://bucketloot-testing.blr1.digitaloceanspaces.com/credentials.json
Discovered POTENTIALLY SENSITIVE FILE[Potential Jenkins credentials file] in https://bucketloot-testing.blr1.digitaloceanspaces.com/credentials.xml
Discovered POTENTIALLY SENSITIVE FILE[Bitcoin Core config] in https://bucketloot-testing.blr1.digitaloceanspaces.com/bitcoin.conf
Discovered POTENTIALLY SENSITIVE FILE[Docker configuration file] in https://bucketloot-testing.blr1.digitaloceanspaces.com/deployment.dockercfg
Discovered URL(s) in https://bucketloot-testing.blr1.digitaloceanspaces.com/dashboard.html
Discovered URL(s) in https://bucketloot-testing.blr1.digitaloceanspaces.com/config.php

{
  "Results": [
    {
      "bucketUrl": "https://bucketloot-testing.blr1.digitaloceanspaces.com/",
      "Assets": [
        {
          "url": "https://blackhat.com/",
          "domain": "blackhat.com",
          "subdomain": ""
        },
        {
          "url": "https://certificates.blackhat.com/",
          "domain": "blackhat.com",
          "subdomain": "certificates.blackhat.com"
        },
        {
          "url": "https://google.com/login",
          "domain": "google.com",
          "subdomain": ""
        },
        {
          "url": "https://firecat.toolswatch.org/",
          "domain": "toolswatch.org",
          "subdomain": "firecat.toolswatch.org"
        },
        {
          "url": "https://www.google.com",
          "domain": "google.com",
          "subdomain": "www.google.com"
        },
        {
          "url": "http://example.com/dashboard",
          "domain": "example.com",
          "subdomain": ""
        },
        {
          "url": "https://www.openai.com",
          "domain": "openai.com",
          "subdomain": "www.openai.com"
        },
        {
          "url": "https://www.example.com/admin",
          "domain": "example.com",
          "subdomain": "www.example.com"
        },
        {
          "url": "https://www.example.com/login.php",
          "domain": "example.com",
          "subdomain": "www.example.com"
        },
        {
          "url": "https://www.example.com/reset-password",
          "domain": "example.com",
          "subdomain": "www.example.com"
        },
        {
          "url": "https://example.com/api/endpoint",
          "domain": "example.com",
          "subdomain": ""
        }
      ],
      "Secrets": [
        {
          "name": "AWS Access Key ID",
          "url": "https://bucketloot-testing.blr1.digitaloceanspaces.com/credentials.json",
          "severity": "CRITICAL"
        }
      ],
      "SensitiveFiles": [
        {
          "name": "Potential Jenkins credentials file",
          "url": "https://bucketloot-testing.blr1.digitaloceanspaces.com/credentials.xml"
        },
        {
          "name": "Bitcoin Core config",
          "url": "https://bucketloot-testing.blr1.digitaloceanspaces.com/bitcoin.conf"
        },
        {
          "name": "Docker configuration file",
          "url": "https://bucketloot-testing.blr1.digitaloceanspaces.com/deployment.dockercfg"
        }
      ]
    }
  ],
  "version": "2.0",
  "Scanned": [
    "https://bucketloot-testing.blr1.digitaloceanspaces.com/"
  ],
  "Skipped": null
}
```