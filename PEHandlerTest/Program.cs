using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PEHandlerTest
{
    internal static class Program
    {
        private static StreamWriter log;

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        private static void Main()
        {
            string baseLoc = Environment.CurrentDirectory;
            string logLoc = $"{baseLoc}/pehandlertest.log";
            Console.WriteLine($"Log location is {logLoc}");
            log = new StreamWriter(logLoc);
            AppDomain.CurrentDomain.ProcessExit += (s, e) => log.Dispose();
            PEHandler.PEFile.Trace = Trace;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TestApp());
        }

        private static void Trace(string msg)
        {
            Console.WriteLine(msg);
            log.WriteLine(msg);
        }
    }
}