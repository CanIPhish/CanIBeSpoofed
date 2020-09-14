using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace canibespoofed_console
{
    class Options
    {

        [Option('o', "output", Default = "", HelpText = "output scanning results into a comma delimited file (e.g. -o \"C:\\results.csv\")")]
        public string output { get; set; }

        [Option('i', "input", Default = "", HelpText = "input scanning results into a comma delimited file (e.g. -o \"C:\\results.csv\")")]
        public string input { get; set; }

        [Option('b', "batch", Default = false, HelpText = "input a pipe delimited list in-place of <filename> for scanning automation")]
        public bool batch { get; set; }

        [Option('h', "help", Default = false, HelpText = "show help message and exit")]
        public bool help { get; set; }
    }
}
