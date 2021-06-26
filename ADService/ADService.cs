using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using callback.CBFSFilter;

namespace ADService
{
    public partial class ADService : ServiceBase
    {
        private Cbfilter mFilter = null;
        private const uint ERROR_PRIVILEGE_NOT_HELD = 1314;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 16;
        private string mGuid = "{713CC6CE-B3E2-4FD9-838D-E28F558F6866}";
        private static string SERVICE_NAME = "ADService";
        private static string SERVICE_LOG = "Application";
        private EventLog evLog = null;
        public const uint DELETE =               0x00010000;
        public const uint READ_CONTROL =         0x00020000;
        public const uint WRITE_DAC =            0x00040000;
        public const uint WRITE_OWNER =          0x00080000;
        public const uint SYNCHRONIZE =          0x00100000;
        public const uint FILE_READ_ATTRIBUTES = 0x00000080; 
        public const uint FILE_READ_EA =         0x00000008; 
        public const uint FILE_READ_DATA =       0x00000001;

        [DllImport("kernel32.dll")]
        static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hFile);

        public ADService()
        {
            InitializeComponent();

            ((ISupportInitialize)(this.EventLog)).BeginInit();
            if (!EventLog.SourceExists(SERVICE_NAME))
            {
                //An event log source should not be created and immediately used.
                //There is a latency time to enable the source, it should be created
                //prior to executing the application that uses the source.
                //Execute this sample a second time to use the new source.
                EventLog.CreateEventSource(SERVICE_NAME, SERVICE_LOG);
            }
            ((ISupportInitialize)(this.EventLog)).EndInit();

            // Create an EventLog instance and assign its source.
            evLog = new EventLog();
            evLog.Source = SERVICE_NAME;
            evLog.Log = SERVICE_LOG;
        }

        protected override void OnStart(string[] args)
        {
            //this.CanStop = false;
            mFilter = new Cbfilter();
            uint versionHigh = 0, versionLow = 0;
            int moduleStatus;
            ulong moduleVersion;

            moduleStatus = mFilter.GetDriverStatus(mGuid);
            moduleVersion = (ulong)mFilter.GetDriverVersion(mGuid);
            versionHigh = (uint)(moduleVersion >> 32);
            versionLow = (uint)(moduleVersion & 0xFFFFFFFF);

            string driveStatus = "Driver: not installed"; ;
            if (moduleStatus != 0)
            {
                driveStatus = string.Format("Driver version: {0}.{1}.{2}.{3}",
                  versionHigh >> 16, versionHigh & 0xFFFF, versionLow >> 16, versionLow & 0xFFFF);
            }

            mFilter.OnAfterOpenFile += onAfterOpenFile;
            mFilter.OnBeforeOpenFile += onBeforeOpenFile;
            mFilter.OnBeforeRenameOrMoveFile += onBeforeRenameOrMoveFile;
            //long fFs = Constants.FS_CE_AFTER_OPEN | Constants.FS_CE_BEFORE_OPEN | Constants.FS_CE_BEFORE_RENAME;
            long fFs = Constants.FS_CE_BEFORE_RENAME | Constants.FS_CE_BEFORE_OPEN;
            mFilter.AddFilterRule("*.activedata", 0, fFs, Constants.FS_NE_ALL);

            mFilter.Initialize(mGuid);
            mFilter.ProcessFailedRequests = true;
            mFilter.ProcessCachedIORequests = true;
            mFilter.Config("AllowFileAccessInBeforeOpen=false;ModifiableReadWriteBuffers=true");
            mFilter.StartFilter(5000);
            mFilter.FileFlushingBehavior = 0;
            evLog.WriteEntry("Service started. "+driveStatus);
            Console.WriteLine("Service started. " + driveStatus);
        }

        protected override void OnStop()
        {
            try
            {
                mFilter.StopFilter(false);
                //evLog.WriteEntry("Service stopped.");
                evLog.Dispose();
            }
            catch (CBFSFilterException err)
            {
                //MessageBox.Show(this, err.Message, "CBFS Filter", MessageBoxButtons.OK, MessageBoxIcon.Error);
                evLog.WriteEntry("Stop: " + err.Message);
            }
        }

        protected override void OnShutdown()
        {
            //this.CanStop = true;
            //base.OnShutdown();
        }

#if NOSERVICE
        public void _onStart(string[] args)
        {
            OnStart(args);
        }

        public void _onStop()
        {
            OnStop();
        }
#endif
        private void onBeforeOpenFile(object Sender, CbfilterBeforeOpenFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();

            //Console.WriteLine("BeforeRead: {0} by process {1}. RD:{2,5}, RA:{3,5}, RC:{4,5}, SY:{5,5}, DA:{6}, OPT:{7}, SM:{8}", fname, process, isGenericRead(e.DesiredAccess), isReadAttributes(e.DesiredAccess), isReadControl(e.DesiredAccess), isSynchronize(e.DesiredAccess), Convert.ToString(e.DesiredAccess, 2).PadLeft(32, '0'), Convert.ToString(e.Options, 2).PadLeft(32, '0'), Convert.ToString(e.ShareMode, 2).PadLeft(32, '0'));
            Console.WriteLine("BeforeRead: {0} by process {1}. RD:{2,5}, RA:{3,5}, RC:{4,5}, SY:{5,5}", fname, process, isReadData(e.DesiredAccess), isReadAttributes(e.DesiredAccess), isReadControl(e.DesiredAccess), isSynchronize(e.DesiredAccess));

            // Access to file system alternate streams is always allowed
            if (fname.EndsWith(":ZONE.IDENTIFIER")) return;

            // Reading of attributes, sync or control is always allowed
            if (!isReadData(e.DesiredAccess) && (isReadControl(e.DesiredAccess) || isReadAttributes(e.DesiredAccess) || isSynchronize(e.DesiredAccess))) {
                return;
            }

            long fsize = 0;
            try
            {
                long fHandler = mFilter.CreateFileDirect(fname, false, 0, 3, 128, false);
                bool result = GetFileSizeEx((IntPtr)fHandler, out fsize);
                if (result)
                {
                    //Console.WriteLine("File size is: " + fsize);
                    result = CloseHandle((IntPtr)fHandler);
                    if (!result)
                    {
                        Console.WriteLine("cannot close file");
                    }
                }
            }
            catch(CBFSFilterCbfilterException ex)
            {
                Console.WriteLine("BeforeOpen: file "+fname+" exception "+ex);
                return;
            }

            // file is being to be read, only notepad allowed
            e.ResultCode = process.Contains("NOTEPAD.EXE") ? 0 : (int)ERROR_PRIVILEGE_NOT_HELD;
            e.ProcessRequest = (e.ResultCode == 0);
            Console.WriteLine("Exiting with PR: {0} and RC: {1}.", e.ProcessRequest, e.ResultCode);
        }
        private void onAfterOpenFile(object Sender, CbfilterAfterOpenFileEventArgs e)
        {
            string fname = e.FileName;
            // Access to file system alternate streams is allowed
            if (e.FileName.ToUpper().EndsWith(":ZONE.IDENTIFIER"))
            {
                return;
            }

            long fsize = new FileInfo(fname).Length;
            if (fsize >= 1024)
            {
                byte[] bytes = new byte[1024];
                using (var stream = File.OpenRead(fname))
                {
                    int count = stream.Read(bytes, 0, 1024);
                    Console.WriteLine("AfterOpen: " + fname + " - read 1k. Process: "+ mFilter.GetOriginatorProcessName());
                    e.ResultCode = (int)5;
                }
            }
        }

        private void onBeforeRenameOrMoveFile(object Sender, CbfilterBeforeRenameOrMoveFileEventArgs e)
        {
            Console.WriteLine("BeforeRename: trying to rename " + e.FileName + " to " + e.NewFileName);
            if (e.NewFileName.ToUpper().Contains(".ACTIVEDATA"))
            {
                e.ProcessRequest = true;
                Console.WriteLine("Allowed!");
            }
            else
            {
                e.ProcessRequest = false;
                Console.WriteLine("Negated!");
            }
        }

        private bool isReadControl(int flag)
        {
            return (flag & READ_CONTROL) == READ_CONTROL;
        }

        private bool isReadAttributes(int flag)
        {
            return (flag & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES;
        }

        private bool isSynchronize(int flag)
        {
            return (flag & SYNCHRONIZE) == SYNCHRONIZE;
        }

        private bool isReadData(int flag)
        {
            return (flag & FILE_READ_DATA) == FILE_READ_DATA;
        }
    }
}
