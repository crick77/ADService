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
using System.Threading;
using adEditor;

namespace ADService
{
    public partial class ADService : ServiceBase
    {
        private Cbfilter mFilter = null;
        private const uint ERROR_ACCESS_DENIED = 5;
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
        [DllImport("kernel32.dll", BestFitMapping = true, CharSet = CharSet.Ansi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpbuffer, UInt32 nNumberofBytesToRead, out UInt32 lpNumberofBytesRead, IntPtr lpOverlapped);
        [DllImport("kernel32.dll")]
        static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, [In] ref System.Threading.NativeOverlapped lpOverlapped);
        [DllImport("kernel32.dll")]
        static extern bool SetFilePointerEx(IntPtr hFile, long liDistanceToMove, IntPtr lpNewFilePointer, uint dwMoveMethod);

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
            else
            {
                Console.WriteLine("Driver not installed!");
                throw new Exception();
            }

            //mFilter.OnAfterOpenFile += onAfterOpenFile;
            //mFilter.OnBeforeOpenFile += onBeforeOpenFile;
            mFilter.OnBeforeReadFile += onBeforeReadFile;
            mFilter.OnBeforeRenameOrMoveFile += onBeforeRenameOrMoveFile;
            //long fFs = Constants.FS_CE_AFTER_OPEN | Constants.FS_CE_BEFORE_OPEN | Constants.FS_CE_BEFORE_RENAME;
            //long fFs = Constants.FS_CE_BEFORE_RENAME | Constants.FS_CE_BEFORE_OPEN;
            long fFs = Constants.FS_CE_BEFORE_RENAME | Constants.FS_CE_BEFORE_READ;
            mFilter.AddFilterRule("*.activedata", 0, fFs, Constants.FS_NE_ALL);

            mFilter.Initialize(mGuid);
            //mFilter.ProcessFailedRequests = true;
            mFilter.ProcessCachedIORequests = true;
            mFilter.Config("AllowFileAccessInBeforeOpen=false;ModifiableReadWriteBuffers=true");
            mFilter.StartFilter(5000);
            mFilter.FileFlushingBehavior = 0;
            evLog.WriteEntry("Service started. "+driveStatus);
            Console.WriteLine("Service started. " + driveStatus + " Active:"+mFilter.Active);
        }

        protected override void OnStop()
        {
            try
            {
                mFilter.StopFilter(true);
                mFilter.Dispose();
                //evLog.WriteEntry("Service stopped.");
                Console.WriteLine("Service stopped.");
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

        private void onBeforeReadFile(object Sender, CbfilterBeforeReadFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();

            Console.WriteLine("BeforeRead: {0} by process {1}, Direction {2}, ReadStart {3}, ReadLen {4}, BuffLen {5}", fname, process, e.Direction, e.Position, e.BytesToRead, e.BufferLength);

            long fsize = 0;
            try
            {
                // Open the file bypassing filter stack...directly to kernel
                long fHandler = mFilter.CreateFileDirect(fname, false, 0, 3, 128, false);
                if (fHandler == 0)
                {
                    e.ProcessRequest = false;
                    e.ResultCode = 6; // ERROR_INVALID_HANDLE
                    return;
                }

                // Get the size of the file and check if the file is at least 2048 bytes long
                bool result = GetFileSizeEx((IntPtr)fHandler, out fsize);
                if (!result || fsize < 2048)
                {
                    CloseHandle((IntPtr)fHandler);
                    e.ProcessRequest = false;
                    e.ResultCode = (fsize < 2048) ? 11 : 6; // 11=ERROR_BAD_FORMAT
                    return;
                }

                // Read the first 2048 bytes and them map them to header format
                byte[] buff = new byte[2048];
                uint buffRead, buffWritten;
                ReadFile((IntPtr)fHandler, buff, 2048, out buffRead, IntPtr.Zero);
                int bSize = Marshal.SizeOf(new ActiveDataFile());
                byte[] adBuff = new byte[bSize];
                for (int i = 0; i < adBuff.Length; ++i) adBuff[i] = buff[i];
                ActiveDataFile adf = ByteArrayToActiveData(adBuff);

                // check if the file is an activedata "magic word"
                if (baToStringNull(adf.magic) != "*AD*")
                {
                    CloseHandle((IntPtr)fHandler);
                    e.ProcessRequest = false;
                    e.ResultCode = 11; // 11=ERROR_BAD_FORMAT
                    return;
                }

                // Determine what operation is beeing done (Open with ADEDITOR or ATTACHMENT)
                //if(isEditor()) {
                //   perform "OnRead" operation but, before executing operation
                //   check if counter/date have expired
                //   if ok, perform operation, recompute hash and save file
                //}
                //if(isShare()) {
                //  perform "OnShare" operation but, before executing operation
                //  check if counter/date have expired
                //  if ok, perform operation, recompute hash and save file
                //}
                UInt64 n = 0; 
                IntPtr ptr = new IntPtr((int)n);
                SetFilePointerEx((IntPtr)fHandler, -buff.Length, IntPtr.Zero, 1); //FILE_BEGIN = 0, FILE_POSITION = 1

                var natOverlap3 = new NativeOverlapped { OffsetLow = (int)0 };
                WriteFile((IntPtr)fHandler, buff, 2048, out buffWritten, ref natOverlap3);

                //Console.WriteLine("File size is: " + fsize);
                result = CloseHandle((IntPtr)fHandler);
                if (!result)
                {
                    Console.WriteLine("cannot close file");
                }                
            }
            catch (CBFSFilterCbfilterException ex)
            {
                Console.WriteLine("BeforeRead: file " + fname + " exception " + ex);
                return;
            }

            if(fsize>e.BytesToRead)
            {
                Console.WriteLine("Invalid request, app shoud read whole file. File size is {0} requested {1}.",fsize, e.BytesToRead);
                e.ResultCode = (int)ERROR_ACCESS_DENIED;
                e.ProcessRequest = false;
                return;
            }

            // file is being to be read, only notepad allowed
            e.ResultCode = process.Contains("ADEDITOR.EXE") ? 0 : (int)ERROR_ACCESS_DENIED;
            if(e.ResultCode==0)
            {
                Console.WriteLine("ADEditor: read allowed!");
            }
            e.ProcessRequest = (e.ResultCode == 0);
            Console.WriteLine("BeforeRead: Exiting with PR: {0} and RC: {1}.", e.ProcessRequest, e.ResultCode);
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

        private string baToStringNull(byte[] b)
        {
            return Encoding.UTF8.GetString(b).Replace('\0', ' ').Trim();
        }

        private ActiveDataFile ByteArrayToActiveData(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                ActiveDataFile stuff = (ActiveDataFile)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(ActiveDataFile));
                return stuff;
            }
            finally
            {
                handle.Free();
            }
        }
    }
}
