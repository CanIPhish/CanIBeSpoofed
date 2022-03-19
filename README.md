## What is CanIBeSpoofed

canibespoofed-console is a console project utilising functionality built for the https://caniphish.com/free-phishing-tools/email-spoofing-test website. This project facilitates scanning of domains to gain visibility over email supply chain and SPF/DMARC vulnerabilities. See https://caniphish.com/free-phishing-tools/email-spoofing-test/features for a full list of capabilities the console project can demonstrate. The console project is designed for use by Information Security professionals who need to scan domains in a more automated fashion than is readily available through the web gui.

### Requirements
Windows 10 Endpoint or Windows Server 2012+ with .NET Framework 4.5 onwards

### Setup
```
git clone https://github.com/Rices/CanIBeSpoofed.git
cd canibespoofed-console\bin\Debug
```
Note: To provide the IP geolocation functionality, the free API @ https://ipgeolocation.io/ is leveraged. However the free API key within the project is limited to 1000 calls a day (between 20-50 domain SPF lookups). It's likely this limit will be hit so I highly recommend creating a free account at IPGeolocation and replacing the listed API key under canibespoofed-console/Spoof_Check/Geolocation.cs. Once saved, rebuild the project through Visual Studio and scan at will :)

## Usage
```Usage: canibespoofed-console [Options] <domain>
Options:
-h, --help         show help message and exit
-b, --batch        switch used to perform a batch scan against multiple domains
-o, --output       output scanning results into a JSON formatted file (e.g. -o "C:\results.json") [only applicable when used with the -b switch]
-i, --input        input a pipe delimited list (e.g. -i "domainList.csv") for batch scanning [only applicable when used with the -b switch]

Example Usage (Single Domain Supply Chain Scan): canibespoofed-console github.com
Example Usage (Bulk Domain High-level Scan): canibespoofed-console -b -i "C:\domainListing.csv" -o "C:\results.json"
```
![](/images/Usage.PNG)

## What core features does canibespoofed provide?
The core features can be broken into 4 categories. It's through the aggregation of these features that we gain a full picture of your email infrastructure. The categories are as follows:
### 1. Identifying SPF & DMARC Issues
We perform 13 checks against SPF & DMARC configurations, as follows:
![](/images/VulnChecks.PNG)

### 2. Extracting Mail Sender Supply Chain
We recursively query your SPF record and all lookups within it, allowing us to identify all IPv4 and IPv6 IP addresses in-use. Once identified, we collate IP ownership information, providing you with a mechanism to see who operates your downstream mail sender infrastructure.

### 3. Visualising Mail Sender Geolocation
Building from the point above, we enhance the view of your mail sender supply chain by pulling near exact geolocation information. We provide this information in both a tabular format but also visualised on a world map. This can assist with identification of geolocation motivated risks - e.g. if you're a Federal Government Agency in a Five-Eyes Country, it would be best to avoid use of mail infrastructure owned by a hostile nations ISP and operated out of said nation.

### 4. Correlating Blacklisted Mail Senders
We subscribe to multiple IP-driven blacklists which identify IPs that are associated with:
* Unsolicated Bulk Emails, Spam Operations & Spam Services (i.e. Low Reputation Senders)
* Snowshoe spam, whereby spammers are actively attempting to evade spam detection (i.e. Low Reputation Senders)
* Hijacked endpoints infected by illegal 3rd party exploits, including open proxies (HTTP, socks, AnalogX, wingate, etc), worms/viruses with built-in spam engines, and other types of trojan-horse exploits.
* End-user (non-MTA) addresses which are dynamically allocated to residential users (i.e. Low Reputation Senders)

## Example Queries

### 1. Supply Chain Query & Vulnerability Analysis (ex. github.com)

![](/images/SupplyChainScan.PNG)

### 2. Batch File Query & Vulnerability Analysis (ex. Top 5 Most Visited Domains)

#### 2.1 Input File:

![](/images/InputFile.PNG)

#### 2.2 Query:

![](/images/BatchScan.PNG)

#### 2.3 Output:

![](/images/outputFile.PNG)
