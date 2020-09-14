using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CanIBeSpoofed.Spoof_Check.Helper
{
    public class GetDomain
    {
        public static string GetDomainName(string url)
        {
            string uriStr = url;
            if (!uriStr.Contains(Uri.SchemeDelimiter))
            {
                uriStr = string.Concat(Uri.UriSchemeHttp, Uri.SchemeDelimiter, uriStr);
            }
            Uri uri = new Uri(uriStr);
            if(uri.Host.Contains("www."))
            {
                int index = uri.Host.IndexOf("www.");
                return (index < 0)
                    ? uri.Host
                    : uri.Host.Remove(index, "www.".Length);
            }
            return uri.Host;
        }
    }
}