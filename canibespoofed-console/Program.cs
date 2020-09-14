using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CanIBeSpoofed.Spoof_Check;
using CanIBeSpoofed.Models;
using CanIBeSpoofed.Spoof_Check.Helper;
using System.IO;
using Newtonsoft.Json;
using Nager.PublicSuffix;
using CommandLine;

namespace canibespoofed_console
{
    class Program
    {
        static void Main(string[] args)
        {
            string inputFile = "";
            string outputFile = "";
            string domainName = "";

            if (args.Length == 0) { HelpMessage(); }
            else
            {
                domainName = args[args.Length - 1];
                Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.help) { HelpMessage(); }
                       else
                       {
                           outputFile = o.output;
                           inputFile = o.input;
                           if (o.batch) { BulkDomainScan(inputFile, outputFile); }
                           else
                           {
                               Console.WriteLine("Scanning underway... Please wait up to 10 seconds.");
                               Console.WriteLine("");
                               SupplyChainDomainScan(domainName);
                           }
                       }
                   });
            }
        }

        public async static void SupplyChainDomainScan(string domainName)
        {
            string parsedDomain = GetDomain.GetDomainName(domainName);
            ParsedSPFRecord spfParse = await new SPFParse().GetSPF(parsedDomain, 1);
            SPFDMARCRecord spfDmarc = new SPFParse().GetSPFDMARCRecord(parsedDomain);
            List<IssueScanResult> issues = new IssueEngine().IssueScan(spfDmarc, spfParse);

            ResultModel spoofResults = new ResultModel();
            spoofResults.issueScan = issues;

            spoofResults.parsedSPFRecordOutput = spfParse;
            spoofResults.domain = parsedDomain;
            if (spfParse != null)
            {
                spoofResults.mapLocation = new Geolocation().MapLocationRollUp(spfParse);
                if (spfDmarc.spfRecord.Contains("redirect="))
                {
                    string[] splitSPF = spfDmarc.spfRecord.Split(' ');
                    int index = Array.FindIndex(splitSPF, x => x.Contains("redirect="));
                    spoofResults.redirectedSPF = new SPFParse().GetSPFDMARCRecord(splitSPF[index].Split('=')[1]).spfRecord;
                }
            }
            spoofResults.dnsResult = spfDmarc;
            PrintSupplyChain(spoofResults);
        }
           
        private static void PrintSupplyChain(ResultModel supplyChainResult)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("---------------------------------------------------");
            Console.WriteLine("-------------------DNS LOOKUP----------------------");
            Console.WriteLine("---------------------------------------------------");
            Console.ResetColor();
            Console.WriteLine("Domain Name: {0}", supplyChainResult.domain);
            Console.WriteLine("---------------------------------------------------");
            Console.WriteLine("SPF Record: {0}", supplyChainResult.dnsResult.spfRecord);
            Console.WriteLine("---------------------------------------------------");
            Console.WriteLine("DMARC Record: {0}", supplyChainResult.dnsResult.dmarcRecord);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("---------------------------------------------------");
            Console.WriteLine("---------------SPOOFABILITY ISSUES-----------------");
            Console.WriteLine("---------------------------------------------------");
            Console.ResetColor();
            if (supplyChainResult.issueScan != null)
            {
                if (supplyChainResult.issueScan.Count != 0)
                {
                    foreach (IssueScanResult issue in supplyChainResult.issueScan)
                    {
                        Console.WriteLine("Code: {0}", issue.code);
                        Console.WriteLine("Title: {0}", issue.title);
                        Console.WriteLine("Detail: {0}", issue.detail);
                        Console.WriteLine("Severity: {0}", issue.severity);
                        Console.WriteLine("---------------------------------------------------");
                    }
                }
                else { Console.WriteLine("No SPF or DMARC Issues Identified - Good work!!!"); }
            }
            else { Console.WriteLine("A parsing error occurred in our issue scanning engine. Please report this to admin@canibespoofed.com"); }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("---------------------------------------------------");
            Console.WriteLine("------------SPF SUPPLY CHAIN ANALYSIS--------------");
            Console.WriteLine("---------------------------------------------------");
            Console.ResetColor();
            if (supplyChainResult.parsedSPFRecordOutput != null)
            {
                Console.WriteLine("---------------------------------------------------");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("SPF Domain: {0}", supplyChainResult.domain);
                Console.ResetColor();
                foreach (IPVulnerabilities ipVulns in supplyChainResult.parsedSPFRecordOutput.ip4Records)
                {
                    Console.WriteLine("---------------------------------------------------");
                    Console.WriteLine("IP Address: {0}", ipVulns.ip4records);
                    Console.WriteLine("Organisation Name: {0}", ipVulns.organisationName);
                    Console.WriteLine("Country Name: {0}", ipVulns.country_name);
                    Console.WriteLine("Spam Score: {0}", ipVulns.spamLookup);
                }

                foreach (IPVulnerabilities ipVulns in supplyChainResult.parsedSPFRecordOutput.ip6Records)
                {
                    Console.WriteLine("---------------------------------------------------");
                    Console.WriteLine("IP Address: {0}", ipVulns.ip4records);
                    Console.WriteLine("Organisation Name: {0}", ipVulns.organisationName);
                    Console.WriteLine("Country Name: {0}", ipVulns.country_name);
                    Console.WriteLine("Spam Score: {0}", ipVulns.spamLookup);
                }

                if (supplyChainResult.parsedSPFRecordOutput.aRecord.Count != 0)
                {
                    foreach (ParsedMXARecord aRecords in supplyChainResult.parsedSPFRecordOutput.aRecord)
                    {
                        Console.WriteLine("---------------------------------------------------");
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("SPF Domain: {0} 'A' Records", aRecords.lookupDomain);
                        Console.ResetColor();
                        foreach (CanIBeSpoofed.Spoof_Check.IPVulnerabilities ipVulns in aRecords.ipLookup)
                        {
                            Console.WriteLine("---------------------------------------------------");
                            Console.WriteLine("IP Address: {0}", ipVulns.ip4records);
                            Console.WriteLine("Organisation Name: {0}", ipVulns.organisationName);
                            Console.WriteLine("Country Name: {0}", ipVulns.country_name);
                            Console.WriteLine("Spam Score: {0}", ipVulns.spamLookup);
                        }
                    }
                }

                if (supplyChainResult.parsedSPFRecordOutput.mxRecord.Count != 0)
                {
                    foreach (ParsedMXARecord mxRecords in supplyChainResult.parsedSPFRecordOutput.mxRecord)
                    {
                        Console.WriteLine("---------------------------------------------------");
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("SPF Domain: {0} 'MX' Records", mxRecords.lookupDomain);
                        Console.ResetColor();
                        foreach (IPVulnerabilities ipVulns in mxRecords.ipLookup)
                        {
                            Console.WriteLine("---------------------------------------------------");
                            Console.WriteLine("IP Address: {0}", ipVulns.ip4records);
                            Console.WriteLine("Organisation Name: {0}", ipVulns.organisationName);
                            Console.WriteLine("Country Name: {0}", ipVulns.country_name);
                            Console.WriteLine("Spam Score: {0}", ipVulns.spamLookup);
                        }
                    }
                }

                foreach (ParsedIncludeRecord includeR in supplyChainResult.parsedSPFRecordOutput.includeRecords)
                {
                    Console.WriteLine("---------------------------------------------------");
                    foreach (ParsedIncludeRecord subInclude in includeR.subLookup.includeRecords)
                    {
                        SPFRecurse(subInclude, includeR.includeRecord);
                        foreach (ParsedIncludeRecord subIncludeThree in subInclude.subLookup.includeRecords)
                        {
                            SPFRecurse(subIncludeThree, subInclude.includeRecord);
                            foreach (ParsedIncludeRecord subIncludeFour in subIncludeThree.subLookup.includeRecords)
                            {
                                SPFRecurse(subIncludeFour, subIncludeThree.includeRecord);
                            }
                        }
                    }
                }
            }
        }

        public static void SPFRecurse(ParsedIncludeRecord subInclude, string parentIncludeRecord)
        {
            if (parentIncludeRecord == "")
            {
                Console.WriteLine("---------------------------------------------------");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("SPF Domain: {0}", subInclude.includeRecord);
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("---------------------------------------------------");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("SPF Domain: {0} : {1}", parentIncludeRecord, subInclude.includeRecord);
                Console.ResetColor();
            }
            foreach (IPVulnerabilities subipVulns in subInclude.subLookup.ip4Records)
            {
                Console.WriteLine("---------------------------------------------------");
                Console.WriteLine("IP Address: {0}", subipVulns.ip4records);
                Console.WriteLine("Organisation Name: {0}", subipVulns.organisationName);
                Console.WriteLine("Country Name: {0}", subipVulns.country_name);
                Console.WriteLine("Spam Score: {0}", subipVulns.spamLookup);
            }
            foreach (CanIBeSpoofed.Spoof_Check.IPVulnerabilities subipVulns in subInclude.subLookup.ip6Records)
            {
                Console.WriteLine("---------------------------------------------------");
                Console.WriteLine("IP Address: {0}", subipVulns.ip4records);
                Console.WriteLine("Organisation Name: {0}", subipVulns.organisationName);
                Console.WriteLine("Country Name: {0}", subipVulns.country_name);
                Console.WriteLine("Spam Score: {0}", subipVulns.spamLookup);
            }
            if (subInclude.subLookup.aRecord.Count != 0)
            {
                foreach (ParsedMXARecord aRecords in subInclude.subLookup.aRecord)
                {
                    Console.WriteLine("---------------------------------------------------");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("SPF Domain: {0} : {1} 'A' Records", subInclude.includeRecord, aRecords.lookupDomain);
                    Console.ResetColor();
                    foreach (CanIBeSpoofed.Spoof_Check.IPVulnerabilities ipVulns in aRecords.ipLookup)
                    {
                        Console.WriteLine("---------------------------------------------------");
                        Console.WriteLine("IP Address: {0}", ipVulns.ip4records);
                        Console.WriteLine("Organisation Name: {0}", ipVulns.organisationName);
                        Console.WriteLine("Country Name: {0}", ipVulns.country_name);
                        Console.WriteLine("Spam Score: {0}", ipVulns.spamLookup);
                    }
                }
            }
            if (subInclude.subLookup.mxRecord.Count != 0)
            {
                foreach (CanIBeSpoofed.Spoof_Check.ParsedMXARecord mxRecords in subInclude.subLookup.mxRecord)
                {
                    Console.WriteLine("---------------------------------------------------");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("SPF Domain: {0} : {1} 'MX' Records", subInclude.includeRecord, mxRecords.lookupDomain);
                    Console.ResetColor();
                    foreach (CanIBeSpoofed.Spoof_Check.IPVulnerabilities ipVulns in mxRecords.ipLookup)
                    {
                        Console.WriteLine("---------------------------------------------------");
                        Console.WriteLine("IP Address: {0}", ipVulns.ip4records);
                        Console.WriteLine("Organisation Name: {0}", ipVulns.organisationName);
                        Console.WriteLine("Country Name: {0}", ipVulns.country_name);
                        Console.WriteLine("Spam Score: {0}", ipVulns.spamLookup);
                    }
                }
            }
        }

        public static void BulkDomainScan(string inputFile, string outputFile)
        {
            List<string> domainList = LoadDomainList(inputFile);
            ScanAndSave(domainList, outputFile);
        }

        private static List<string> LoadDomainList(string inputFile)
        {
            DomainParser domainParser = new DomainParser(new WebTldRuleProvider());
            List<string> govDomain = new List<string>();
            using (var reader = new StreamReader(@inputFile))
            {
                while (!reader.EndOfStream)
                {
                    string fullDomain = reader.ReadLine();
                    govDomain.Add(fullDomain);
                    Console.WriteLine(fullDomain);
                }
            }
            return govDomain;
        }

        private static async void ScanAndSave(List<string> domainList, string outputFile)
        {
            List<SubDomainOutput> domainsAggregated = new List<SubDomainOutput>();
            int i = 1;
            foreach (string uniqueDomain in domainList)
            {
                Console.WriteLine("Count: {0}", i);
                i++;
                SubDomainOutput domainModel = new SubDomainOutput();
                domainModel.SubDomain = uniqueDomain;
                Console.WriteLine("-------------------------");
                Console.WriteLine("Domain Name: {0}", uniqueDomain);
                SPFParse getSPFDMARC = new SPFParse();
                SPFDMARCRecord spfDMARC = getSPFDMARC.GetSPFDMARCRecord(domainModel.SubDomain);
                
                ParsedSPFRecord spfParse = await new SPFParseScheduler().GetSPF(domainModel.SubDomain, 1);

                List<IssueScanResult> issues = new IssueEngine().IssueScan(spfDMARC, spfParse);

                string issueSeverity = "";
                foreach (IssueScanResult issue in issues)
                {
                    if (issue.severity == "Very High")
                    {
                        issueSeverity = issue.severity;
                    }
                    if (issueSeverity != "Very High")
                    {
                        if (issue.severity == "High")
                        {
                            issueSeverity = issue.severity;
                        }
                        if (issueSeverity != "High")
                        {
                            if (issue.severity == "Medium")
                            {
                                issueSeverity = issue.severity;
                            }
                            if (issueSeverity != "Medium")
                            {
                                if (issue.severity == "Low")
                                {
                                    issueSeverity = issue.severity;
                                }
                            }
                        }
                    }
                }
                domainModel.Spoofable = issueSeverity;
                if (spfDMARC.spfRecord == null) { domainModel.SPFRecord = ""; }
                else { domainModel.SPFRecord = spfDMARC.spfRecord; }
                if (spfDMARC.dmarcRecord == null) { domainModel.DMARCRecord = ""; }
                else
                {
                    if (spfDMARC.dmarcRecord.Contains("; p=none") || spfDMARC.dmarcRecord.Contains(";p=none"))
                    {
                        domainModel.DMARCRecord = "Audit";
                    }
                    else if (spfDMARC.dmarcRecord.Contains("; p=quarantine") || spfDMARC.dmarcRecord.Contains(";p=quarantine"))
                    {
                        domainModel.DMARCRecord = "Quarantine";
                    }
                    else if (spfDMARC.dmarcRecord.Contains("; p=reject") || spfDMARC.dmarcRecord.Contains(";p=reject"))
                    {
                        domainModel.DMARCRecord = "Reject";
                    }
                    else
                    {
                        domainModel.DMARCRecord = "-";
                    }
                }
                domainModel.searchEngine = "N/A";
                domainsAggregated.Add(domainModel);

                Console.WriteLine("Spoof Rating: {0}", domainModel.Spoofable);
                Console.WriteLine("SPF Record: {0}", domainModel.SPFRecord);
                Console.WriteLine("DMARC Record: {0}", domainModel.DMARCRecord);
            }

            // serialize JSON directly to a file
            using (StreamWriter file = File.CreateText(outputFile))
            {
                JsonSerializer serializer = new JsonSerializer();
                serializer.Serialize(file, domainsAggregated);
            }
            Console.WriteLine("");
            Console.WriteLine("All domains have been scanned. The results are viewable at: {0}", outputFile);
        }

        private static void HelpMessage()
        {
            Console.WriteLine("canibespoofed-console 0.01 - see https://github.com/Rices/CanIBeSpoofed for updates \n\n" +
                    "canibespoofed-console is a lightweight wrapper utilising functionality from the canibespoofed \n" +
                    "website. This project facilitates scanning of domains to gain visibility over email supply chain and  \n" +
                    "SPF/DMARC vulnerabilities. See https://canibespoofed.com/Home/Features for a full list of capabilities \n" +
                    "the console project can demonstrate. The console project is designed for use by Information Security professionals\n" +
                    "who need to scan domains in a more automated fashion than is readily available through the web gui.\n" +
                    "\n\nUsage: canibespoofed-console [Options] <domain>" +
                    "\nOptions:" +
                    "\n-h, --help         show help message and exit" +
                    "\n-b, --batch        switch used to perform a batch scan against multiple domains" +
                    "\n-o, --output       output scanning results into a JSON formatted file (e.g. -o \"C:\\results.json\") [only applicable when used with the -b switch]" +
                    "\n-i, --input        input a pipe delimited list (i.e. .csv file) for batch scanning [only applicable when used with the -b switch]" +
                    "\n\n" +
                    "Example Usage (Single Domain Supply Chain Scan): canibespoofed-console github.com\n" +
                    "Example Usage (Bulk Domain High-level Scan): canibespoofed-console -b -i \"C:\\domainListing.csv\" -o \"C:\\results.json\"");
        }
    }
}
