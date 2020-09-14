using ARSoft.Tools.Net.Dns;
using CanIBeSpoofed.Models;
using Nager.PublicSuffix;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using CanIBeSpoofed.Spoof_Check;

namespace CanIBeSpoofed.Spoof_Check
{
    public class SPFParse
    {
        public List<MapLocation> MapLocations = new List<MapLocation>();

        public async Task<ParsedSPFRecord> GetSPF(string domainName, int lookupCount)
        {
            try
            {
                if (lookupCount <= 15)
                {
                    string spfRecord = null;
                    IDnsResolver resolver = new DnsStubResolver();
                    List<TxtRecord> txtRecords = resolver.Resolve<TxtRecord>(domainName, RecordType.Txt);

                    foreach (TxtRecord ip in txtRecords)
                    {
                        if (ip.TextData.Contains("v=spf1 "))
                        {
                            spfRecord = ip.TextData;
                        }
                    }
                    if (spfRecord.IsNullOrWhiteSpace()) return null;
                    return await ParseSPFOutput(spfRecord.Split(' '), domainName, lookupCount);
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        public SPFDMARCRecord GetSPFDMARCRecord(string domainName)
        {
            bool longSPF = false;
            SPFDMARCRecord dnsRecord = new SPFDMARCRecord();
            dnsRecord.domainName = domainName;
            try
            {
                IDnsResolver resolver = new DnsStubResolver();
                List<TxtRecord> txtRecords = resolver.Resolve<TxtRecord>(domainName, RecordType.Txt);
                foreach (TxtRecord ip in Enumerable.Reverse(txtRecords))
                {
                    if (ip.TextData.Contains("v=spf1 "))
                    {
                        dnsRecord.spfRecord = ip.TextData;
                        if (!ip.TextData.Contains("+all") && !ip.TextData.Contains("~all") && !ip.TextData.Contains("-all") && !ip.TextData.Contains("?all")) { longSPF = true; }
                    }
                    else if (longSPF)
                    {
                        if (ip.TextData.Contains("+all") || ip.TextData.Contains("~all") || ip.TextData.Contains("-all") || ip.TextData.Contains("?all")) { dnsRecord.spfRecord += ip.TextData; }
                    }
                }
                try
                {
                    txtRecords = resolver.Resolve<TxtRecord>("_dmarc." + domainName, RecordType.Txt);
                    foreach (TxtRecord ip in txtRecords)
                    {
                        if (ip.TextData.Contains("v=DMARC1"))
                        {
                            dnsRecord.dmarcRecord = ip.TextData;
                        }
                    }
                    if (dnsRecord.dmarcRecord.IsNullOrWhiteSpace())
                    {
                        throw new Exception();
                    }
                }
                catch
                {
                    DomainParser domainParser = new DomainParser(new WebTldRuleProvider());
                    string parentDomain = domainParser.Get(domainName).RegistrableDomain;

                    txtRecords = resolver.Resolve<TxtRecord>("_dmarc." + parentDomain, RecordType.Txt);
                    foreach (TxtRecord ip in txtRecords)
                    {
                        if (ip.TextData.Contains("v=DMARC1"))
                        {
                            dnsRecord.dmarcRecord = ip.TextData;
                        }
                    }
                }
            }
            catch
            {
                return dnsRecord;
            }
            return dnsRecord;
        }

        private async Task<ParsedSPFRecord> ParseSPFOutput(string[] spfOutput, string domainName, int lookupCount)
        {
            ParsedSPFRecord spfModel = new ParsedSPFRecord();
            Parallel.ForEach(spfOutput, async spfSubstring =>
            {
                if (spfSubstring.Contains("ip4:")) { spfModel.ip4Records.Add(SPFIPWhoIsLookup(spfSubstring.Split(':')[1], domainName)); }
                if (spfSubstring.Contains("ip6:")) { spfModel.ip6Records.Add(SPFIPWhoIsLookup(spfSubstring.Split(new string[] { "ip6:" }, StringSplitOptions.None)[1], domainName)); } //need to update
                if (spfSubstring.Contains("ptr:")) { spfModel.ptrRecords.Add(spfSubstring.Split(':')[1]); } //need to update
                if (spfSubstring.Contains("include:") || spfSubstring.Contains("redirect="))
                {
                    ParsedIncludeRecord includeRecords = new ParsedIncludeRecord();
                    SPFParse spfNew = new SPFParse();
                    if (spfSubstring.Contains("include:")) { includeRecords.includeRecord = spfSubstring.Split(':')[1]; }
                    else { includeRecords.includeRecord = spfSubstring.Split('=')[1]; }
                    includeRecords.subLookup = await spfNew.GetSPF(includeRecords.includeRecord, ++lookupCount);
                    if(includeRecords.subLookup == null) { includeRecords.subLookup = new ParsedSPFRecord(); }
                    spfModel.includeRecords.Add(includeRecords);
                }
                if (spfSubstring.Equals("a") || spfSubstring.Equals("+a")) { lookupCount++; spfModel.aRecord.AddRange(CustomDNSLookup(domainName, "a")); }
                if (spfSubstring.Contains("a:")) { lookupCount++; spfModel.aRecord.AddRange(CustomDNSLookup(spfSubstring.Split(':')[1], "a")); }
                if (spfSubstring.Equals("mx") || spfSubstring.Equals("+mx")) { lookupCount++; spfModel.mxRecord.AddRange(CustomDNSLookup(domainName, "mx")); }
                if (spfSubstring.Contains("mx:")) { lookupCount++; spfModel.mxRecord.AddRange(CustomDNSLookup(spfSubstring.Split(':')[1], "mx")); }
                if (spfSubstring.Contains("exists:")) { lookupCount++; spfModel.existsRecords.Add(spfSubstring.Split(':')[1]); } //need to update
            });
            spfModel.mapLocations = MapLocations;
            spfModel.lookupCount = lookupCount;
            return spfModel;
        }

        public List<ParsedMXARecord> CustomDNSLookup(string domainName, string recordType)
        {
            List<ParsedMXARecord> customLookup = new List<ParsedMXARecord>();
            IDnsResolver resolver = new DnsStubResolver();
            try
            {

                if (recordType == "mx")
                {
                    List<MxRecord> mxRecords = resolver.Resolve<MxRecord>(domainName, RecordType.Mx);
                    List<ARecord> aRecords = null;
                    List<IPVulnerabilities> ipVulns = new List<IPVulnerabilities>();
                    foreach(MxRecord mxRecord in mxRecords)
                    {
                        aRecords = resolver.Resolve<ARecord>(mxRecord.ExchangeDomainName, RecordType.A);
                        foreach (ARecord aRecord in aRecords)
                        {
                            if (!aRecord.Address.ToString().IsNullOrWhiteSpace())
                            {
                                ipVulns.Add(SPFIPWhoIsLookup(aRecord.Address.ToString(), domainName));
                            }
                        }
                    }
                    customLookup.Add(new ParsedMXARecord() { ipLookup = ipVulns, lookupDomain = domainName });
                }
                if (recordType == "a")
                {
                    List<ARecord> aRecords = resolver.Resolve<ARecord>(domainName, RecordType.A);
                    List<IPVulnerabilities> ipVulns = new List<IPVulnerabilities>();
                    foreach (ARecord aRecord in aRecords)
                    {
                        if (!aRecord.Address.ToString().IsNullOrWhiteSpace())
                        {
                            ipVulns.Add(SPFIPWhoIsLookup(aRecord.Address.ToString(), domainName));
                        }
                    }
                    customLookup.Add(new ParsedMXARecord() { ipLookup = ipVulns, lookupDomain = domainName });
                }

                return customLookup;
            }
            catch
            {
                return customLookup;
            }
        }

        public IPVulnerabilities SPFIPWhoIsLookup(string ip4, string domain)
        {
            if (MapLocations.Count <= 50)
            {
                IPVulnerabilities ipV = new IPVulnerabilities();
                Geolocation geoIP = new Geolocation();
                GeoLocationOutput geoOutput = geoIP.GetIPGeoLocation(ip4.Split('/')[0]);
                SpamhausLookup spamhaus = new SpamhausLookup();
                ipV.country_name = geoOutput.Country_Name;
                ipV.state_prov = geoOutput.State_Prov;
                ipV.organisationName = geoOutput.Organisation;
                MapLocations.Add(new MapLocation() { Title = geoOutput.Organisation, Lat = geoOutput.Latitude, Lng = geoOutput.Longitude, Country = geoOutput.Country_Name, IPAddress = ip4 });
                if (ipV.organisationName.IsNullOrWhiteSpace()) { ipV.organisationName = new WhoisLookup().QueryByIPAddress(ip4).OrganizationName; };
                ipV.ip4records = ip4;
                ipV.spamLookup = spamhaus.GetSpamhausBlocklist(ip4.Split('/')[0]);
                ipV.lookupDomain = domain;
                return ipV;
            }
            else
            {
                return new IPVulnerabilities() { ip4records = ip4, organisationName = "**Too many lookups**", country_name = " - ", spamLookup = " - " };
            }
        }

        public bool SubDomainSPFNotExists(string domainName)
        {
            try
            {
                IDnsResolver resolver = new DnsStubResolver();
                List<TxtRecord> txtRecords = resolver.Resolve<TxtRecord>(domainName, RecordType.Txt);
                DomainParser domainParser = new DomainParser(new WebTldRuleProvider());
                string parentDomain = domainParser.Get(domainName).RegistrableDomain;

                txtRecords = resolver.Resolve<TxtRecord>("test1231312312." + parentDomain, RecordType.Txt);
                foreach (TxtRecord ip in txtRecords)
                {
                    if (ip.TextData.Contains("v=spf1 "))
                    {
                        return false;
                    }
                }
                return true;
            }
            catch
            {
                return true;
            }
        }
    }

    public class ParsedSPFRecord
    {
        public List<MapLocation> mapLocations = new List<MapLocation>();
        public List<IPVulnerabilities> ip4Records = new List<IPVulnerabilities>();
        public List<IPVulnerabilities> ip6Records = new List<IPVulnerabilities>();
        public List<string> ptrRecords = new List<string>();
        public List<ParsedIncludeRecord> includeRecords = new List<ParsedIncludeRecord>();
        public List<ParsedMXARecord> aRecord = new List<ParsedMXARecord>();
        public List<ParsedMXARecord> mxRecord = new List<ParsedMXARecord>();
        public List<string> existsRecords = new List<string>();
        public int lookupCount { get; set; }
    }

    public class ParsedIncludeRecord
    {
        public string includeRecord { get; set; }
        public ParsedSPFRecord subLookup = new ParsedSPFRecord();
    }

    public class ParsedMXARecord
    {
        public string lookupDomain { get; set; }
        public List<IPVulnerabilities> ipLookup { get; set; }
    }

    public class IPVulnerabilities
    {
        public string ip4records { get; set; }
        public string organisationName { get; set; }
        public string country_name { get; set; }
        public string state_prov { get; set; }
        public string spamLookup { get; set; }
        public string lookupDomain { get; set; }
    }

    public class SPFDMARCRecord
    {
        public string domainName { get; set; }
        public string spfRecord { get; set; }
        public string dmarcRecord { get; set; }
    }
}