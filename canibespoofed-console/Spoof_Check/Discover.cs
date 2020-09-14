using CanIBeSpoofed.Spoof_Check.Helper;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using CanIBeSpoofed.Spoof_Check;

namespace CanIBeSpoofed.Spoof_Check
{
    public class Discover
    {
        List<SubDomainOutput> subDomains = new List<SubDomainOutput>();
        string engine;
        public async Task<List<SubDomainOutput>> SubDomainDiscovery(string domain, int searchEngine)
        {
            var cmd = "";
            switch (searchEngine)
            {
                case 0:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e Netcraft -v -d " + domain;
                    engine = "Netcraft";
                    break;
                case 1:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e DNSdumpster -v -d " + domain;
                    engine = "DNSdumpster";
                    break;
                case 2:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e Virustotal -v -d " + domain;
                    engine = "Virustotal";
                    break;
                case 3:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e PassiveDNS -v -d " + domain;
                    engine = "PassiveDNS";
                    break;
                case 4:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e Bing -v -d " + domain;
                    engine = "Bing";
                    break;
                case 5:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e ThreatCrowd -v -d " + domain;
                    engine = "ThreatCrowd";
                    break;
                case 6:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e Google -v -d " + domain;
                    engine = "Google";
                    break;
                case 7:
                    cmd = @"-u C:\Sublist3r\sublist3r.py -e Yahoo -v -d " + domain;
                    engine = "Yahoo";
                    break;
            }
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = @"C:\Python\python.exe",
                    Arguments = cmd,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                },
                EnableRaisingEvents = true
            };
            process.ErrorDataReceived += Process_OutputDataReceived;
            process.OutputDataReceived += Process_OutputDataReceived;

            process.Start();
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();
            process.WaitForExit(20000);
            return subDomains;
        }

        private async void Process_OutputDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (!e.Data.IsNullOrWhiteSpace())
            {
                if (e.Data.Contains(": ") && !e.Data.Contains("[!] Error") && !e.Data.Contains("[-] Total Unique") && !e.Data.Contains("DeprecationWarning:"))
                {
                    SubDomainOutput subdomain = new SubDomainOutput();
                    subdomain.SubDomain = e.Data.Split(':')[1].Trim();
                    Console.WriteLine(e.Data);
                    SPFParse getSPFDMARC = new SPFParse();
                    SPFDMARCRecord spfDMARC = getSPFDMARC.GetSPFDMARCRecord(subdomain.SubDomain);
                    Console.WriteLine("-------------------------");
                    ParsedSPFRecord spfParse = await new SPFParseScheduler().GetSPF(subdomain.SubDomain, 1);

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
                    subdomain.Spoofable = issueSeverity;
                    if (spfDMARC.spfRecord.IsNullOrWhiteSpace()) { subdomain.SPFRecord = "-"; }
                    else { subdomain.SPFRecord = spfDMARC.spfRecord; }
                    if (spfDMARC.dmarcRecord.IsNullOrWhiteSpace()) { subdomain.DMARCRecord = "-"; }
                    else
                    {
                        if (spfDMARC.dmarcRecord.Contains("; p=none") || spfDMARC.dmarcRecord.Contains(";p=none"))
                        {
                            subdomain.DMARCRecord = "Audit";
                        }
                        else if (spfDMARC.dmarcRecord.Contains("; p=quarantine") || spfDMARC.dmarcRecord.Contains(";p=quarantine"))
                        {
                            subdomain.DMARCRecord = "Quarantine";
                        }
                        else if (spfDMARC.dmarcRecord.Contains("; p=reject") || spfDMARC.dmarcRecord.Contains(";p=reject"))
                        {
                            subdomain.DMARCRecord = "Reject";
                        }
                        else
                        {
                            subdomain.DMARCRecord = "-";
                        }
                    }
                    subdomain.searchEngine = engine;
                    subDomains.Add(subdomain);

                    Console.WriteLine(subdomain.Spoofable);
                    Console.WriteLine(subdomain.SubDomain);
                }
            }
        }
    }

    public static class StringExtensions
    {
        public static bool IsNullOrWhiteSpace(this string value)
        {
            if (value != null)
            {
                for (int i = 0; i < value.Length; i++)
                {
                    if (!char.IsWhiteSpace(value[i]))
                    {
                        return false;
                    }
                }
            }
            return true;
        }
    }

    public class SubDomainOutput
    {
        public string SubDomain { get; set; }
        public string SPFRecord { get; set; }
        public string DMARCRecord { get; set; }
        public string Spoofable { get; set; }
        public string searchEngine { get; set; }
    }
}