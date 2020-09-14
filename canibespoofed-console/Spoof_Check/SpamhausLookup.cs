using DnsClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;

namespace CanIBeSpoofed.Spoof_Check
{
    public class SpamhausLookup
    {
        public string GetSpamhausBlocklist(string ip)
        {
            string[] parsedIP = ip.Split('.');
            Array.Reverse(parsedIP);
            string reversedIP = "";
            foreach(string subIP in parsedIP)
            {
                reversedIP += subIP + ".";
            }
            try
            {
                if (Int32.TryParse((Dns.GetHostAddresses(reversedIP + "zen.spamhaus.org")[0].ToString().Split('.')[3]), out int spamParsed))
                {
                    if (spamParsed == 2) { return "IP Address involved in sending unsolicated bulk emails, spam operations & spam services. Mail is highly likely to be blocked by receiving mail servers."; }
                    if (spamParsed == 3) { return "IP Address involved in sending snowshoe spam - whereby spammers are actively attempting to evade spam detection. Mail is likely to be blocked by receiving mail servers"; }
                    if (new[] { 4, 5, 6, 7 }.Contains(spamParsed)) { return "The IP Address host has been infected by illegal 3rd party exploits, including open proxies (HTTP, socks, AnalogX, wingate, etc), worms/viruses with built-in spam engines, and other types of trojan-horse exploits."; }
                    if (new[] { 10, 11 }.Contains(spamParsed)) { return "The IP Address is a end-user non-MTA IP address, reserved by the corresponding ISP for residential use. Mail is highly likely to result in email spam and be blocked by receiving mail servers."; }
                    else { return "Error"; }
                }
            }
            catch
            {
                return "Clean";
            }
            return "Clean";
        }
    }
}