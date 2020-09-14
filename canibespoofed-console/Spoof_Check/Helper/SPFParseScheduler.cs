using ARSoft.Tools.Net.Dns;
using CanIBeSpoofed.Models;
using Nager.PublicSuffix;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace CanIBeSpoofed.Spoof_Check.Helper
{
    public class SPFParseScheduler
    {

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

        private async Task<ParsedSPFRecord> ParseSPFOutput(string[] spfOutput, string domainName, int lookupCount)
        {
            ParsedSPFRecord spfModel = new ParsedSPFRecord();
            Parallel.ForEach(spfOutput, async spfSubstring =>
            {
                if (spfSubstring.Contains("include:"))
                {
                    ParsedIncludeRecord includeRecords = new ParsedIncludeRecord();
                    SPFParseScheduler spfNew = new SPFParseScheduler();
                    includeRecords.includeRecord = spfSubstring.Split(':')[1];
                    includeRecords.subLookup = await spfNew.GetSPF(includeRecords.includeRecord, ++lookupCount);
                    if (includeRecords.subLookup == null) { includeRecords.subLookup = new ParsedSPFRecord(); }
                    spfModel.includeRecords.Add(includeRecords);
                }
            });
            spfModel.lookupCount = lookupCount;
            return spfModel;
        }
    }
}