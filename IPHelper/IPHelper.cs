using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using Microsoft.PowerShell.Commands;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Management.Automation.Runspaces;

namespace IPHelper
{
    /// <summary>
    /// PowerShell Cmdlet for generating a list of IPs in a given
    /// IP Range by CIDR or Start and End IP Addresses in a range.
    /// </summary>
    [Cmdlet(VerbsCommon.Get,"IPRange", DefaultParameterSetName = "CIDR")]
    public class GetIPRange: PSCmdlet
    {
        private string cidr;
        private string startIP;
        private string endIP;

        [Parameter(Mandatory = true,
            Position = 0,
            ParameterSetName = "CIDR",
            ValueFromPipelineByPropertyName = true)]
        public string CIDR
        {
            get { return this.cidr; }
            set { cidr = value; }
        }

        [Parameter(Mandatory = true,
            Position = 0,
            ParameterSetName = "Range",
            ValueFromPipelineByPropertyName = true)]
        public string StartIP
        {
            get { return this.startIP; }
            set { startIP = value; }
        }

        [Parameter(Mandatory = true,
            Position = 1,
            ParameterSetName = "Range",
            ValueFromPipelineByPropertyName = true)]
        public string EndIP
        {
            get { return this.endIP; }
            set { endIP = value; }
        }

        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "CIDR":
                    this.GetIPRangeByCIDR(cidr);
                    break;
                case "Range":
                    this.GetRange(startIP, endIP);
                    break;
                default:
                    break;
            }
        }

        protected void GetRange(string StartIp, string EndIp)
        {
            var ipTool = new IPTool();
            int start = ipTool.IPToInt(StartIp);
            int end = ipTool.IPToInt(EndIp);

            for (int i = start; i <= end; i++)
            {
                byte[] bytes = BitConverter.GetBytes(i);
                WriteObject(new IPAddress(new[] { bytes[3], bytes[2], bytes[1], bytes[0] }));
            }
        }

        protected void GetIPRangeByCIDR(string CIDRNet)
        {
            string[] cidr = CIDRNet.Split('/');
            var ipTool = new IPTool();

            // Parse values for network.
            int ip = ipTool.IPToInt(cidr[0]);
            int bits = Convert.ToInt32(cidr[1]);
            int mask = ~((1 << (32 - bits)) - 1);
            int network = ip & mask;
            int broadcast = network + ~mask;
            int startIP = network + 1;
            int endIP = broadcast - 1;
            int usableIps = (bits > 30) ? 0 : (broadcast - network - 1);
           
            // Generate list
            for (int i = startIP; i <= endIP; i++)
            {
                byte[] bytes = BitConverter.GetBytes(i);
                WriteObject(new IPAddress(new[] { bytes[3], bytes[2], bytes[1], bytes[0] }));
            }
        }

        
    }


    /// <summary>
    /// PowerShell Cmdlet for performing a ARP Scan against a given
    /// IP Range by CIDR or start and end IP addresses in a range.
    /// </summary>
    [Cmdlet(VerbsLifecycle.Invoke, "ARPScan", DefaultParameterSetName = "CIDR")]
    public class InvokeARPScan : PSCmdlet
    {
        private string cidr;
        private string startIP;
        private string endIP;

        [Parameter(Mandatory = true,
            Position = 0,
            ParameterSetName = "CIDR",
            ValueFromPipelineByPropertyName = true)]
        public string CIDR
        {
            get { return this.cidr; }
            set { cidr = value; }
        }

        [Parameter(Mandatory = true,
            Position = 0,
            ParameterSetName = "Range",
            ValueFromPipelineByPropertyName = true)]
        public string StartIP
        {
            get { return this.startIP; }
            set { startIP = value; }
        }

        [Parameter(Mandatory = true,
            Position = 1,
            ParameterSetName = "Range",
            ValueFromPipelineByPropertyName = true)]
        public string EndIP
        {
            get { return this.endIP; }
            set { endIP = value; }
        }
 
        // Load the required API needed to sen ARP requests.
        [System.Runtime.InteropServices.DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

        protected override void ProcessRecord()
        {

            var pipeline = Runspace.DefaultRunspace.CreateNestedPipeline();
            Command cmd = new Command("Get-IPRange");

            // Set the proper parameter depending on the set name.
            switch (ParameterSetName)
            {
                case "CIDR":
                    cmd.Parameters.Add("CIDR", cidr);
                    
                    break;
                case "Range":
                    cmd.Parameters.Add("StartIP", startIP);
                    cmd.Parameters.Add("EndIP", endIP);
                    break;
                default:
                    break;
            }

            pipeline.Commands.Add(cmd);

            foreach (var ip in pipeline.Invoke())
            {
                WriteVerbose("Trying " + ip.ToString());
                var macAddress = GetMacAddress(ip.ToString());
                if (macAddress != "")
                {
                    // Custom object for the result of a succesful resolution.
                    var arpPresult = new PSObject();
                    arpPresult.Properties.Add(new PSNoteProperty("IPAddress", ip.ToString()));
                    arpPresult.Properties.Add(new PSNoteProperty("MACAddress", macAddress));
                    arpPresult.TypeNames.Insert(0,"IPHelper.ARPResponse");
                    WriteObject(arpPresult);
                }
            }
            
        }

        public static string GetMacAddress(String addr)
        {
            IPAddress IPaddr = IPAddress.Parse(addr);
            byte[] mac = new byte[6];
            int L = 6;

            SendARP(BitConverter.ToInt32(IPaddr.GetAddressBytes(), 0), 0, mac, ref L);
            String macAddr = BitConverter.ToString(mac, 0, L);
            return (macAddr.Replace('-', ':'));
        }
    }


    public sealed class IPTool
    {
        /// <summary>
        /// Returns a host count for the given CIDR.
        /// </summary>
        /// <param name="CIDR"></param>
        /// <returns></returns>
        public int HostCount(string CIDR)
        {
            string[] cidr = CIDR.Split('/');
            // Parse values for network.
            int ip = IPToInt(cidr[0]);
            int bits = Convert.ToInt32(cidr[1]);
            int mask = ~((1 << (32 - bits)) - 1);
            int network = ip & mask;
            int broadcast = network + ~mask;
            int usableIps = (bits > 30) ? 0 : (broadcast - network - 1);

            return usableIps;
        }


        /// <summary>
        /// Returns a host count given a Start IP and End IP of a range.
        /// </summary>
        /// <param name="startIP"></param>
        /// <param name="endIP"></param>
        /// <returns></returns>
        public int HostCount(string startIP, string endIP)
        {
            var startIntval = IPAddress.NetworkToHostOrder(IPToInt(startIP));
            var endtIntval = IPAddress.NetworkToHostOrder(IPToInt(endIP));
            var hosts = (startIntval - endtIntval) + 1;

            return hosts;

        }


        /// <summary>
        /// Takes an IP representation and returns its Int32 value.
        /// </summary>
        /// <param name="IPString"></param>
        /// <returns></returns>
        public int IPToInt(String IPString)
        {
            byte[] octets = IPAddress.Parse(IPString).GetAddressBytes();
            int ipint = BitConverter.ToInt32(new byte[] { octets[3], octets[2], octets[1], octets[0] }, 0);
            return ipint;
        }

    }
}
