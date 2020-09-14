using DnsClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using CanIBeSpoofed.Spoof_Check;

namespace CanIBeSpoofed.Spoof_Check
{
    public class IssueEngine
    {
        private List<string> rolledIncludeRecords = new List<string>();


        public List<IssueScanResult>  IssueScan(SPFDMARCRecord spfDMARCRecord, ParsedSPFRecord extendedSPF)
        {
            List<IssueScanResult> issueResults = new List<IssueScanResult>();
            issueResults.AddRange(SPFIssueScan(spfDMARCRecord.spfRecord, spfDMARCRecord.domainName, extendedSPF));
            if (issueResults.Count >= 1)
            {
                if (!issueResults[0].code.Equals(0) && !issueResults[0].code.Equals(11))
                {
                    issueResults = DMARCIssueScan(spfDMARCRecord.dmarcRecord, spfDMARCRecord.domainName, issueResults);
                }
            }
            else
            {
                issueResults = DMARCIssueScan(spfDMARCRecord.dmarcRecord, spfDMARCRecord.domainName, issueResults);
            }
            return issueResults;
        }

        private List<IssueScanResult> SPFIssueScan(string spfRecord, string domainName, ParsedSPFRecord parsedSPF)
        {
            List<IssueScanResult> spfIssues = new List<IssueScanResult>();
            if (new SPFParse().SubDomainSPFNotExists(domainName)) { spfIssues.Add(issueDescriptors(6, domainName)); }
            if (spfRecord.IsNullOrWhiteSpace())
            {
                try
                {
                    LookupClient lookupClient = new LookupClient(new LookupClientOptions() { ThrowDnsErrors = true });
                    var resultClient = lookupClient.Query(domainName, QueryType.A);
                    spfIssues.Add(issueDescriptors(1, domainName));
                }
                catch (DnsResponseException e)
                {
                    if(e.Code.ToString().Equals((@"NotExistentDomain")))
                    {
                        try
                        {
                            LookupClient lookupClient = new LookupClient(new LookupClientOptions() { ThrowDnsErrors = true });
                            var resultClient = lookupClient.Query(domainName, QueryType.CNAME);
                            spfIssues.Add(issueDescriptors(1, domainName));
                        }
                        catch
                        {
                            spfIssues.Add(issueDescriptors(0, domainName));
                        }
                    }
                    else
                    {
                        spfIssues.Add(issueDescriptors(11, domainName));
                    }
                }
            }
            else
            {
                if (spfRecord.Contains("redirect="))
                {
                    string[] splitSPF = spfRecord.Split(' ');
                    int index = Array.FindIndex(splitSPF, x => x.Contains("redirect="));
                    spfRecord = new SPFParse().GetSPFDMARCRecord(splitSPF[index].Split('=')[1]).spfRecord;
                }
                if (spfRecord.Contains("+all")) { spfIssues.Add(issueDescriptors(3, domainName)); }
                else if (spfRecord.Contains("~all")) { spfIssues.Add(issueDescriptors(4, domainName)); }
                else if (!spfRecord.Contains("-all") || spfRecord.Contains("?all")) { spfIssues.Add(issueDescriptors(2, domainName)); }

                if(includeRollUp(parsedSPF) > 10) { spfIssues.Add(issueDescriptors(5, domainName)); }

                var hashset = new HashSet<string>();
                foreach (string include in rolledIncludeRecords)
                {
                    if (!hashset.Add(include))
                    {
                        spfIssues.Add(issueDescriptors(12, domainName));
                    }
                }

            }

            return spfIssues;
        }

        private List<IssueScanResult> DMARCIssueScan(string dmarcRecord, string domainName, List<IssueScanResult> spfIssues)
        {
            List<IssueScanResult> dmarcIssues = new List<IssueScanResult>();
            List<IssueScanResult> updatedIssues = new List<IssueScanResult>();
            if(dmarcRecord.IsNullOrWhiteSpace())
            {
                dmarcIssues.Add(issueDescriptors(7, domainName));
            }
            else
            {
                if (dmarcRecord.Contains("; p=none") || dmarcRecord.Contains(";p=none"))
                {
                    dmarcIssues.Add(issueDescriptors(8, domainName));
                }
                if (dmarcRecord.Contains("sp=none"))
                {
                    dmarcIssues.Add(issueDescriptors(9, domainName));
                }
                if (dmarcRecord.Contains("pct=") && !dmarcRecord.Contains("pct=100"))
                {
                    dmarcIssues.Add(issueDescriptors(10, domainName));
                }
            }
            if(!dmarcIssues.Exists(x => x.code.Equals(7)) && !dmarcIssues.Exists(x => x.code.Equals(8)) && !dmarcIssues.Exists(x => x.code.Equals(10)))
            {
                foreach (IssueScanResult spfIssue in spfIssues)
                {
                    if (spfIssue.code != 3)
                    {
                        updatedIssues.Add(issueDescriptorUpdate(spfIssue));
                    }
                    else
                    {
                        updatedIssues.Add(spfIssue);
                    }
                }
            }
            else
            {
                updatedIssues.AddRange(spfIssues);
            }
            updatedIssues.AddRange(dmarcIssues);
            return updatedIssues;
        }

        public int includeRollUp(ParsedSPFRecord parsedSPF)
        {
            int lookupCount = 0;
            lookupCount += includeRollUpHelper(parsedSPF);

            foreach (ParsedIncludeRecord spf in parsedSPF.includeRecords)
            {
                lookupCount += includeRollUpHelper(spf.subLookup);
                rolledIncludeRecords.Add(spf.includeRecord);

                foreach (ParsedIncludeRecord spfSub in spf.subLookup.includeRecords)
                {
                    lookupCount += includeRollUpHelper(spfSub.subLookup);
                    rolledIncludeRecords.Add(spfSub.includeRecord);

                    foreach (ParsedIncludeRecord spfSubTwo in spfSub.subLookup.includeRecords)
                    {
                        lookupCount += includeRollUpHelper(spfSubTwo.subLookup);
                        rolledIncludeRecords.Add(spfSubTwo.includeRecord);

                        foreach (ParsedIncludeRecord spfSubThree in spfSubTwo.subLookup.includeRecords)
                        {
                            lookupCount += includeRollUpHelper(spfSubThree.subLookup);
                            rolledIncludeRecords.Add(spfSubThree.includeRecord);

                            foreach (ParsedIncludeRecord spfSubFour in spfSubThree.subLookup.includeRecords)
                            {
                                lookupCount += includeRollUpHelper(spfSubFour.subLookup);
                                rolledIncludeRecords.Add(spfSubFour.includeRecord);
                            }
                        }
                    }
                }
            }
            return lookupCount;
        }

        public int includeRollUpHelper(ParsedSPFRecord parsedSPFInclude)
        {
            int lookupCount = 0;
            if (parsedSPFInclude != null)
            {
                lookupCount += parsedSPFInclude.aRecord.Count;
                lookupCount += parsedSPFInclude.includeRecords.Count;
                lookupCount += parsedSPFInclude.mxRecord.Count;
                lookupCount += parsedSPFInclude.existsRecords.Count;
                lookupCount += parsedSPFInclude.ptrRecords.Count;
            }
            return lookupCount;
        }

        private IssueScanResult issueDescriptorUpdate(IssueScanResult issueResult)
        {
            issueResult.detail = "This issue has been mitigated through the DMARC policy 'p' qualifier being set to 'Quarantine' or 'Reject'. See the Features page to understand what the unmitigated issue relates to.";
            issueResult.severity = "Mitigated";
            return issueResult;
        }

        private IssueScanResult issueDescriptors (int code, string domain)
        {
            IssueScanResult issueResult = new IssueScanResult();
            switch (code)
            {
                case 0:
                    issueResult.code = 0;
                    issueResult.title = "Non-existent domain";
                    issueResult.detail = "The DNS resolver raised an NXDomain error for" + domain + ". Mail receivers will be unable to resolve a DNS response for your domain and will almost certainly flag any mail as spam.";
                    issueResult.severity = "Low";
                    break;
                case 1:
                    issueResult.code = 1;
                    issueResult.title = "No SPF record exists";
                    issueResult.detail = "There is no SPF DNS record for " + domain + ". Mail receivers have no mechanism to determine what your authorised mail servers are. Mail receivers will pass authentication checks with a \"None\" result, indicating no check could be performed. Spoofed emails are likely to be accepted.";
                    issueResult.severity = "High";

                    break;
                case 2:
                    issueResult.code = 2;
                    issueResult.title = "SPF \"all\" mechanism is missing or set to \"?all\"";
                    issueResult.detail = "The \"all\" mechanism at the end of the end of an SPF record tells receivers how to treat unauthorised (i.e. spoofed) emails - if the mechanism is missing or set to \"?all\", authentication checks will always return a \"Neutral\" result which many receivers interpret to accept all mail from " + domain + " (including spoofed emails).";
                    issueResult.severity = "High";
                    break;
                case 3:
                    issueResult.code = 3;
                    issueResult.title = "SPF \"+all\" mechanism set";
                    issueResult.detail = "The \"all\" mechanism at the end of the end of an SPF record tells receivers how to treat unauthorised (i.e. spoofed) emails - the \"+all\" setting tells receivers to pass/accept all mail from " + domain + " (including spoofed emails).";
                    issueResult.severity = "Very High";
                    break;
                case 4:
                    issueResult.code = 4;
                    issueResult.title = "SPF \"~all\" (SoftFail) mechanism set";
                    issueResult.detail = "The \"all\" mechanism at the end of the end of an SPF record tells receivers how to treat unauthorised (i.e. spoofed) emails - the \"~all\" setting tells receivers to 'SoftFail' (i.e. quarantine) emails that fail SPF authentication. In practice however, many email filters  only slightly raise the total spam score  and accept 'SoftFailed' (i.e. spoofed) emails.";
                    issueResult.severity = "Medium";
                    break;
                case 5:
                    issueResult.code = 5;
                    issueResult.title = "SPF has too many lookups for receiver validation";
                    issueResult.detail = "The SPF record requires more than 10 DNS lookups for the validation process. The RFC states that maximum 10 lookups are allowed. As a result, recipients may throw a PermError instead of proceeding with SPF validation. Recipients treat these errors differently than a hard or soft SPF fail , but some will continue processing the mail (i.e. accept spoofed emails).";
                    issueResult.severity = "Medium";
                    break;
                case 6:
                    issueResult.code = 6;
                    issueResult.title = "No SPF sub-domain record exists";
                    issueResult.detail = "The SPF sub-domain policy is a catch-all mechanism used to prevent threat actors from maliciously spoofing sub-domains from which an explicit SPF record hasn't been set. This is typically represented through a DNS entry similar to \"* IN TXT v=spf1 -all\", effectively telling recipients to block mail if an explicit SPF entry for the sub-domain hasn't been set.";
                    issueResult.severity = "Medium";
                    break;
                case 7:
                    issueResult.code = 7;
                    issueResult.title = "No DMARC record exists";
                    issueResult.detail = "There is no DMARC DNS Record set for the domain. Spoofed emails utilising an attack technique known as SPF-bypass are likely to be accepted. See FAQs for more information.";
                    issueResult.severity = "High";
                    break;
                case 8:
                    issueResult.code = 8;
                    issueResult.title = "Insecure DMARC policy 'p' qualifier";
                    issueResult.detail = "The DMARC policy 'p' qualifier is \"none\". If the DMARC policy is neither \"reject\" nor \"quarantine\", spoofed emails utilising an attack technique known as SPF-bypass are likely to be accepted. See FAQs for more information.";
                    issueResult.severity = "High";
                    break;
                case 9:
                    issueResult.code = 9;
                    issueResult.title = "Insecure DMARC sub-domain 'p' qualifier";
                    issueResult.detail = "The DMARC policy 'p' qualifier for sub-domains is set to \"none\". If the DMARC policy is neither \"reject\" nor \"quarantine\", spoofed emails from any " + domain + " sub-domain utilising an attack technique known as SPF-bypass are likely to be accepted. See FAQs for more information.";
                    issueResult.severity = "High";
                    break;
                case 10:
                    issueResult.code = 10;
                    issueResult.title = "Partial DMARC coverage";
                    issueResult.detail = "The DMARC \"pct\" value is set to less than '100' (i.e. 100%), meaning the DMARC policy will only be applied to a percentage of incoming mail. A threat actor can continously deliver spoofed emails (via SPF-bypass) until the DMARC policy isn't applied and mail is accepted. See FAQs for more information.";
                    issueResult.severity = "Medium";
                    break;
                case 11:
                    issueResult.code = 11;
                    issueResult.title = "DNS Timeout during Scan";
                    issueResult.detail = "There was a DNS timeout when querying " + domain + ". This will result in an SPF temperror and any mail will almost certainly be flagged as spam by mail receivers";
                    issueResult.severity = "Low";
                    break;
                case 12:
                    issueResult.code = 12;
                    issueResult.title = "Trivial SPF recurse loop";
                    issueResult.detail = "The SPF record is configured whereby an infinite lookup loop exists in the validation chain for " + domain + ". This will likely result in an SPF PermError. Recipients will treat these errors differently than a hard or soft SPF fail , but many will continue processing the mail (i.e. accept spoofed emails).";
                    issueResult.severity = "Medium";
                    break;
            }
            return issueResult;
        }
    }

    public class IssueScanResult
    {
        public int code { get; set; }

        public string title { get; set; }

        public string detail { get; set; }

        public string severity { get; set; }
    }
}