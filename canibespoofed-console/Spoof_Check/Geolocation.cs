using CanIBeSpoofed.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;

namespace CanIBeSpoofed.Spoof_Check
{
    public class Geolocation
    {

        //Replace API Key for ipgeolocation.io
        private string APIKey = "7426bc3ea2af4827b99d2bd79bf8134a";
        public GeoLocationOutput GetIPGeoLocation(string ip)
        {
            //dynamic geoOutput;
            GeoLocationOutput geoOutput;
            // Create a request for the URL.
            WebRequest request = WebRequest.Create("https://api.ipgeolocation.io/ipgeo?apiKey=" + APIKey + "&ip=" + ip);
            // If required by the server, set the credentials.
            request.Credentials = CredentialCache.DefaultCredentials;

            // Get the response.
            WebResponse response = request.GetResponse();
            // Display the status.
            //Console.WriteLine(((HttpWebResponse)response).StatusDescription);

            // Get the stream containing content returned by the server.
            // The using block ensures the stream is automatically closed.
            using (Stream dataStream = response.GetResponseStream())
            {
                // Open the stream using a StreamReader for easy access.
                StreamReader reader = new StreamReader(dataStream);
                // Read the content.
                geoOutput = Newtonsoft.Json.JsonConvert.DeserializeObject<GeoLocationOutput>(reader.ReadToEnd());
            }

            // Close the response.
            response.Close();
            return geoOutput;
        }

        public List<MapLocation> MapLocationRollUp (ParsedSPFRecord parsedSPF)
        {
            List<MapLocation> mapLocations = new List<MapLocation>();
            mapLocations = parsedSPF.mapLocations;
            foreach(ParsedIncludeRecord spf in parsedSPF.includeRecords)
            {
                mapLocations.AddRange(spf.subLookup.mapLocations);
                foreach (ParsedIncludeRecord spfSub in spf.subLookup.includeRecords)
                {
                    mapLocations.AddRange(spfSub.subLookup.mapLocations);
                    foreach (ParsedIncludeRecord spfSubTwo in spfSub.subLookup.includeRecords)
                    {
                        mapLocations.AddRange(spfSubTwo.subLookup.mapLocations);
                        foreach (ParsedIncludeRecord spfSubThree in spfSubTwo.subLookup.includeRecords)
                        {
                            mapLocations.AddRange(spfSubThree.subLookup.mapLocations);
                        }
                    }
                }
            }
            return mapLocations;
        }
    }

    public class GeoLocationOutput
    {
        [JsonProperty("country_name")]
        public string Country_Name { get; set; }

        [JsonProperty("state_prov")]
        public string State_Prov { get; set; }

        [JsonProperty("organization")]
        public string Organisation { get; set; }

        [JsonProperty("latitude")]
        public double Latitude { get; set; }

        [JsonProperty("longitude")]
        public double Longitude { get; set; }
    }
}