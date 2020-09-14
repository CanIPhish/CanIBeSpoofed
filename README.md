## What is canibespoofed-console

canibespoofed-console is a console project utilising functionality built for the canibespoofed website. This project facilitates scanning of domains to gain visibility over email supply chain and SPF/DMARC vulnerabilities. See https://canibespoofed.com/Home/Features for a full list of capabilities the console project can demonstrate. The console project is designed for use by Information Security professionals who need to scan domains in a more automated fashion than is readily available through the web gui.

### Requirements
Windows 10 Endpoint or Windows Server 2012+ with .NET Framework 4.5 onwards

### Setup
```
git clone https://github.com/Rices/CanIBeSpoofed.git
cd canibespoofed-console\bin\Debug
```
All done!!

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

### Supply Chain Query and Output (ex. github.com)

![](/images/SupplyChainScan.PNG)

### Batch File Query and Output (ex. Top 5 Most Visited Domains)

#### Input File:

![](/images/InputFile.PNG)

#### Query:

![](/images/BatchScan.PNG)

#### Output:

![](/images/outputFile.PNG)
