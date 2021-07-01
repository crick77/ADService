using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace ADService
{
    class PlatformMail
    {
        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

        public static string[] CommandLineToArgs(string commandLine)
        {
            int argc;
            var argv = CommandLineToArgvW(commandLine, out argc);
            if (argv == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception();
            try
            {
                var args = new string[argc];
                for (var i = 0; i < args.Length; i++)
                {
                    var p = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                    args[i] = Marshal.PtrToStringUni(p);
                }

                return args;
            }
            finally
            {
                Marshal.FreeHGlobal(argv);
            }
        }
        public static MailClient[] getInstalledMailClients()
        {
            RegistryKey HKLM = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            RegistryKey mc = HKLM.OpenSubKey("SOFTWARE\\Clients\\Mail");
            string[] mclist = mc.GetSubKeyNames();

            MailClient[] clients = new MailClient[mclist.Length];
            for(int i = 0;i<mclist.Length;i++)
            {
                RegistryKey m = mc.OpenSubKey(mclist[i] + "\\shell\\open\\command");
                string cmd = m.GetValue("").ToString();
                m.Close();

                string[] cmdargs = CommandLineToArgs(cmd);
                string fpath = System.IO.Path.GetFullPath(cmdargs[0]);
                clients[i] = new MailClient(mclist[i], fpath);
            }
            mc.Close();
            HKLM.Close();

            return clients;
        }
    }

    class MailClient {
        private string _Name;
        private string _ExecutablePath;
        public string Name => _Name;
        public string ExecutablePath => _ExecutablePath;

        public MailClient(string Name, string ExecutablePath)
        {
            this._Name = Name;
            this._ExecutablePath = ExecutablePath;
        }
    }
}
