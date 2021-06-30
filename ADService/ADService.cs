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
        private const uint ERROR_INVALID_HANDLE = 6;
        private const uint ERROR_BAD_FORMAT = 11;
        private const uint ERROR_PRIVILEGE_NOT_HELD = 1314;        
        private const uint FILE_ATTRIBUTE_DIRECTORY = 16;
        private string mGuid = "{713CC6CE-B3E2-4FD9-838D-E28F558F6866}";
        private static string SERVICE_NAME = "ADService";
        private static string SERVICE_LOG = "Application";
        private static string ADLIST_FILE = "c:/processed.adlist";
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

            mFilter.OnBeforeReadFile += OnBeforeReadFile;
            mFilter.OnBeforeRenameOrMoveFile += OnBeforeRenameOrMoveFile;
            mFilter.OnBeforeWriteFile += OnBeforeWriteFile;
            long adFS = Constants.FS_CE_BEFORE_RENAME | Constants.FS_CE_BEFORE_READ;
            long genericFS = Constants.FS_CE_BEFORE_WRITE;
            mFilter.AddFilterRule("*.activedata", 0, adFS, Constants.FS_NE_ALL);
            mFilter.AddFilterRule("*.adlist", 0, adFS, Constants.FS_NE_ALL);
            mFilter.AddFilterRule("*.*", 0, genericFS, Constants.FS_NE_ALL);

            mFilter.Initialize(mGuid);
            mFilter.ProcessCachedIORequests = true;
            mFilter.Config("AllowFileAccessInBeforeOpen=false;ModifiableReadWriteBuffers=true");
            mFilter.StartFilter(5000);
            mFilter.FileFlushingBehavior = 0;
            evLog.WriteEntry("Service started. "+ driveStatus + " Active:" + mFilter.Active);
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

        /*
         * The BeforeOpen event is only applied to .ADLIST file where the service records all the
         * already processed files. The opening, renaming and moving of this file is forbidden.
         * 
         * */
        public void OnBeforeOpenFile(object sender, CbfilterBeforeOpenFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();

            if (fname.EndsWith(".ADLIST"))
            {
                Console.WriteLine("The list file is opened...block it");
                e.ProcessRequest = false;
                e.ResultCode = (int)ERROR_ACCESS_DENIED;                
            }
        }

        /*
         * The rename of .ADLIST file is forbidden in any case
         * The rename or move of and .ACTIVEDATA file is, instead, allowed only if the user
         * change the name BUT NOT the file extension.         
         * 
         * */
        private void OnBeforeRenameOrMoveFile(object Sender, CbfilterBeforeRenameOrMoveFileEventArgs e)
        {            
            string fname = e.FileName.ToUpper();
            string newfname = e.NewFileName.ToUpper();
            string process = mFilter.GetOriginatorProcessName().ToUpper();

            Console.WriteLine("BeforeRename: {0} process is trying to rename {1} to {2}.", process, fname, newfname);

            // The adlist file is only allowed by driver
            if (fname.EndsWith(".ADLIST"))
            {
                Console.WriteLine("The list file is beeing moved or renamed...block it");
                e.ProcessRequest = false;
                e.ResultCode = (int)ERROR_ACCESS_DENIED;
                return;
            }

            
            if (newfname.EndsWith(".ACTIVEDATA"))
            {
                e.ProcessRequest = true;
                Console.WriteLine("Allowed!");
            }
            else
            {
                e.ProcessRequest = false;
                e.ResultCode = (int)ERROR_ACCESS_DENIED;
                Console.WriteLine("Negated!");
            }

            // to be removed
            // updateProcessedFile("sdjfhskjfhsjkdhfkjsd " + fname);
        }

        /*
         * The BeforeRead event is applied only to activedata/adlist files
         * 
         *
         *
         */
        private void OnBeforeReadFile(object Sender, CbfilterBeforeReadFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();

            Console.WriteLine("BeforeRead: {0} by process {1}, Direction {2}, ReadStart {3}, ReadLen {4}, BuffLen {5}", fname, process, e.Direction, e.Position, e.BytesToRead, e.BufferLength);

            // The adlist file is only allowed by driver, any other process cannot read it
            if (fname.EndsWith(".ADLIST"))
            {
                Console.WriteLine("The list file is beeing opened by another process...block it");
                e.ProcessRequest = false;
                e.ResultCode = (int)ERROR_ACCESS_DENIED;
                return;
            }

            long fsize = 0;
            try
            {
                // Open the file bypassing filter stack...directly to kernel (parameters MUST be fixed later!)
                long fHandler = mFilter.CreateFileDirect(fname, false, 0, 3, 128, false);
                if (fHandler == 0)
                {
                    e.ProcessRequest = false;
                    e.ResultCode = (int)ERROR_INVALID_HANDLE;
                    return;
                }

                // Get the size of the file and check if the file is at least 2048 bytes long (the minimum size of activedata file)
                bool result = GetFileSizeEx((IntPtr)fHandler, out fsize);
                if (!result || fsize < 2048)
                {
                    CloseHandle((IntPtr)fHandler);
                    e.ProcessRequest = false;
                    e.ResultCode = (fsize < 2048) ? (int)ERROR_BAD_FORMAT : (int)ERROR_INVALID_HANDLE; 
                    return;
                }

                // Read the first 2048 bytes and them map them to header format
                byte[] buff = new byte[2048];
                uint buffRead;
                ReadFile((IntPtr)fHandler, buff, 2048, out buffRead, IntPtr.Zero);
                int bSize = Marshal.SizeOf(new ActiveDataFile());
                byte[] adBuff = new byte[bSize];
                for (int i = 0; i < adBuff.Length; ++i) adBuff[i] = buff[i];
                ActiveDataFile adf = ByteArrayToActiveData(adBuff);

                // check if the file is an activedata "magic word"
                if (baToStringNull(adf.magic) != "*AD*")
                {
                    Console.WriteLine("BeforeRead: file {0} is not an activedata.", fname);
                    CloseHandle((IntPtr)fHandler);
                    e.ProcessRequest = false;
                    e.ResultCode = (int)ERROR_BAD_FORMAT;
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
                /*
                UInt64 n = 0; 
                IntPtr ptr = new IntPtr((int)n);
                SetFilePointerEx((IntPtr)fHandler, -buff.Length, IntPtr.Zero, 1); //FILE_BEGIN = 0, FILE_POSITION = 1

                var natOverlap3 = new NativeOverlapped { OffsetLow = (int)0 };
                WriteFile((IntPtr)fHandler, buff, 2048, out buffWritten, ref natOverlap3);
                */
                //Console.WriteLine("File size is: " + fsize);
                CloseHandle((IntPtr)fHandler);                
            }
            catch (CBFSFilterCbfilterException ex)
            {
                Console.WriteLine("BeforeRead: file " + fname + " exception " + ex);
                e.ProcessRequest = false;
                e.ResultCode = ex.Code;
                return;
            }

            // an allowed app is trying to read a file with too small buffers? (we need it??)
            //if(fsize>e.BytesToRead)
            //{
            //    Console.WriteLine("Invalid request, app shoud read whole file. File size is {0} requested {1}.",fsize, e.BytesToRead);
            //    e.ResultCode = (int)ERROR_ACCESS_DENIED;
            //    e.ProcessRequest = false;
            //    return;
            //}

            // file is being to be read, only adEditor program can read it!
            e.ResultCode = isAdProcess(process) ? 0 : (int)ERROR_ACCESS_DENIED;
            if(e.ResultCode==0)
            {
                Console.WriteLine("ADEditor: read allowed!");
            }
            else
            {
                Console.WriteLine("Unhautorized app trying to read file!");
            }
            e.ProcessRequest = (e.ResultCode == 0);
            Console.WriteLine("BeforeRead: Exiting with PR: {0} and RC: {1}.", e.ProcessRequest, e.ResultCode);
        }

        /*
         * BeforeWrite check all file written to disk. If the first 4 bytes of the buffer contains the magic
         * word "*AD*" it then must keep track of the filename and rename it after the closing to .activedata
         * if the extension is different. Essentially a browser or mail client is tryin to save the attachment
         * with "save as..." renaming it - so it will skip any further checks.
         * 
         * */
        public void OnBeforeWriteFile(object sender, CbfilterBeforeWriteFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();

            Console.WriteLine("BeforeRead: Process: {0}, File: {1}, Len: {2}, ToWrite: {3}, Pos: {4}", process, fname, e.BufferLength, e.BytesToWrite, e.Position);

            // Magic word of file is stored in the first 4 bytes of file. To make things more robust maybe we will put another magic word in the
            // first 16 bytes of file...hope no commercial software writes 1 byte at time!
            if(e.BufferLength>3 && e.Position==0)
            {
                byte[] head = new byte[e.BufferLength];
                try
                {
                    Marshal.Copy(e.Buffer, head, 0, e.BufferLength);

                    string s = Encoding.UTF8.GetString(head);
                    if (s == "*AD*" && !fname.EndsWith(".ACTIVEDATA"))
                    {
                        Console.WriteLine("Writing ActiveData file but with different name!!");
                        // keep track of this file...when closing we must rename it!
                        // we should use Context?? How??
                    }
                }
                catch(System.AccessViolationException ex)
                {
                    Console.WriteLine("Cannot copy buffer due to: " + ex);
                }
            }
        }

        // HELPER FUNCTIONS...TO BE CLEARED!

        private bool isAdProcess(string process)
        {
            if (process.Contains("ADEDITOR.EXE")) return true;

            return false;
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

        private void updateProcessedFile(String text) { 
            using (StreamWriter sw = File.AppendText(ADLIST_FILE))
            {
                sw.WriteLine(text);                
            }	
        }

        private bool isGenericFile(string fname)
        {
            return !fname.EndsWith(".ACTIVEDATA") || !fname.EndsWith(".ADLIST");
        }
    }
}
