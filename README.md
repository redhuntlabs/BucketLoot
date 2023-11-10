<h1 align="center">BucketLoot</h1>
<p align="center"><b>An Automated S3-compatible Bucket Inspector</b></p>
<p align="center">
<a href="#description">Description</a> • <a href="#features">Features</a> • <a href="docs/documentation.md">Documentation</a> • <a href="#acknowledgements">Acknowledgements</a><br><br>
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-AWS-yellow?logo=amazon">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-GCP-red?logo=googlecloud">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-DigitalOcean-blue?logo=digitalocean">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-Custom%20Domains-green?logo=gear">
</p>
<hr>
<img src="./toolscreenshot.png">
<hr style="width:300px; height: 1px; margin: auto; margin-top: 20px;" />
<br>
<div id="description">
<h2> Description </h2>
BucketLoot is an automated S3-compatible Bucket inspector that can help users extract assets, flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text.
<br><br>
The tool can scan for buckets deployed on Amazon Web Services (AWS), Google Cloud Storage (GCS), DigitalOcean Spaces and even custom domains/URLs which could be connected to these platforms. It returns the output in a JSON format, thus enabling users to parse it according to their liking or forward it to any other tool for further processing.
<br><br>
BucketLoot comes with a guest mode by default, which means a user doesn't needs to specify any API tokens / Access Keys initially in order to run the scan. The tool will scrape a maximum of 1000 files that are returned in the XML response and if the storage bucket contains more than 1000 entries which the user would like to run the scanner on, they can provide platform credentials to run a complete scan. If you'd like to know more about the tool, make sure to check out our <a href="https://redhuntlabs.com/blog/introducing-bucketloot-an-automated-cloud-bucket-inspector/">blog</a>.
</div>
<hr style="height: 1px;">
<div id="features">
<h2> Features </h2>

<h4> Secret Scanning </h4>
Scans for over 80+ unique RegEx signatures that can help in uncovering secret exposures tagged with their severity from the misconfigured storage bucket. Users have the ability to modify or add their own signatures in the <a href="./regexes.json">regexes.json</a> file. If you believe you have any cool signatures which might be helpful for others too and could be flagged at scale, go ahead and make a PR!

<h4> Sensitive File Checks</h4>
Accidental sensitive file leakages are a big problem that affects the security posture of individuals and organisations. BucketLoot comes with a 80+ unique regEx signatures list in <a href="./vulnFiles.json">vulnFiles.json</a> which allows users to flag these sensitive files based on file names or extensions.

<h4> Dig Mode </h4>
Want to quickly check if any target website is using a misconfigured bucket that is leaking secrets or any other sensitive data? Dig Mode allows you to pass non-S3 targets and let the tool scrape URLs from response body for scanning.

<h4> Asset Extraction </h4>
Interested in stepping up your asset discovery game? BucketLoot extracts all the URLs/Subdomains and Domains that could be present in an exposed storage bucket, enabling you to have a chance of discovering hidden endpoints, thus giving you an edge over the other traditional recon tools.

<h4> Searching </h4>
The tool goes beyond just asset discovery and secret exposure scanning by letting users search for custom keywords and even Regular Expression queries which may help them find exactly what they are looking for.
</div>

<hr style="height: 1px;">

<div id="acknowledgements">
<h2> Acknowledgements </h2>
<ul type="disc">
<li><a href="https://www.blackhat.com/us-23/arsenal/schedule/#bucketloot---an-automated-s-bucket-inspector-33536">Black Hat USA 2023 [Arsenal]</a></li>
<li><a href="https://blackhatmea.com/session/bucketloot-automated-s3-bucket-inspector">Black Hat MEA 2023</a></li>
<li><a href="https://www.blackhat.com/eu-23/arsenal/schedule/index.html#bucketloot---an-automated-s-compatible-bucket-inspector-35800">Black Hat EU 2023</a></li>
</ul>
</div>

*[`To know more about our Attack Surface Management platform, check out NVADR.`](https://redhuntlabs.com/nvadr)*
