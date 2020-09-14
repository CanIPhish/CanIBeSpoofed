using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CanIBeSpoofed.Models
{
    public class MapLocation
    {
        public string Title { get; set; }
        public double Lat { get; set; }
        public double Lng { get; set; }

        public string IPAddress { get; set; }

        public string Country { get; set; }
    }
}