using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;

namespace CanIBeSpoofed.Spoof_Check.Helper
{
    public class Top100Helper
    {
        public List<Top100Output> DownloadTop100Json(string url)
        {

            List<Top100Output> topOutput;
            // Create a request for the URL.
            WebRequest request = WebRequest.Create(url);
            // If required by the server, set the credentials.
            request.Credentials = CredentialCache.DefaultCredentials;

            // Get the response.
            WebResponse response = request.GetResponse();
            // Display the status.
            Console.WriteLine(((HttpWebResponse)response).StatusDescription);

            // Get the stream containing content returned by the server.
            // The using block ensures the stream is automatically closed.
            using (Stream dataStream = response.GetResponseStream())
            {
                // Open the stream using a StreamReader for easy access.
                StreamReader reader = new StreamReader(dataStream);
                // Read the content.
                topOutput = Newtonsoft.Json.JsonConvert.DeserializeObject<List<Top100Output>>(reader.ReadToEnd());
            }

            // Close the response.
            response.Close();
            return topOutput;
        }

        public class Top100Output
        {
            [JsonProperty("Global_Rank")]
            public int Global_Rank { get; set; }

            [JsonProperty("Domain")]
            public string Domain { get; set; }

            [JsonProperty("Monthly_Visits")]
            public string Monthly_Visits { get; set; }

            [JsonProperty("Parent_Org")]
            public string Parent_Org { get; set; }

            [JsonProperty("Country")]
            public string Country { get; set; }

            [JsonProperty("Spoofable")]
            public string Spoofable { get; set; }
        }
    }
}