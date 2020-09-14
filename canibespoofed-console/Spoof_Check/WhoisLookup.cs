using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Whois.NET;

namespace CanIBeSpoofed.Spoof_Check
{
    public class WhoisLookup
    {
        public WhoisResponse QueryByIPAddress(string ip)
        {
            string ipParsed = ip.Split('/')[0];
            return WhoisClient.Query(ipParsed);
        }

        public async Task<WhoisResponse> QueryByDomain(string domain)
        {
            return await WhoisClient.QueryAsync(domain);
            //Console.WriteLine("{0}", result.OrganizationName); // "Google Inc."
            //Console.WriteLine(string.Join(" > ", result.RespondedServers)); // "whois.iana.org > whois.verisign-grs.com > whois.markmonitor.com" 
            //Console.WriteLine("----------------");
            //Console.WriteLine(result.Raw);
        }
    }
    public class WhoIsData
    {
        public string AddressRangeBegin { get; set; }
        public string AddressRangeEnd { get; set; }
        public string OrganizationName { get; set; }
        public string RawOutput { get; set; }
    }
}