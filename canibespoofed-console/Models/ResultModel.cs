using CanIBeSpoofed.Spoof_Check;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CanIBeSpoofed.Models
{
    public class ResultModel
    {
        public List<IssueScanResult> issueScan { get; set; }
        public ParsedSPFRecord parsedSPFRecordOutput { get; set; }
        public string domain { get; set; }

        public WhoisLookup whoIs = new WhoisLookup();

        public List<MapLocation> mapLocation = new List<MapLocation>();

        public SPFDMARCRecord dnsResult = new SPFDMARCRecord();

        public string redirectedSPF { get; set; }

    }
}