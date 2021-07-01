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
using System.Security.Cryptography;
using MintPlayer.PlatformBrowser;

namespace ADService
{
    public partial class ADService : ServiceBase
    {
        // Filter object and GUID
        private Cbfilter mFilter = new Cbfilter();        
        private string mGuid = "{713CC6CE-B3E2-4FD9-838D-E28F558F6866}";
        // Logging event viewer parameters
        private EventLog evLog = new EventLog();
        private static string SERVICE_NAME = "ADService";
        private static string SERVICE_LOG = "Application";
        // Already processed list file
        private List<string> alreadyProcessed = new List<string>();
        // SHA1 hashing object
        private SHA1Managed sha1 = new SHA1Managed();
        // Error codes
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_HANDLE = 6;
        private const int ERROR_BAD_FORMAT = 11;
        private const uint ERROR_PRIVILEGE_NOT_HELD = 1314;
        private const uint ERROR_AD_EXIRED = 0xA007052E;                
        // Useful constants        
        private static string ACTIVEDATA_EXTENSION = ".ACTIVEDATA";
        private static string ADLIST_EXTENSION = ".ADLIST";
        private static string ADLIST_FILE = "c:/processed" + ADLIST_EXTENSION;
        private static string ADEDITOR_HASH = "ED9F98C07054E9EB8FD7E3BE9CCB22868A33F1FF";
        // File access constants (winapi CreateFileA/W)
        private const int DELETE = 0x00010000;
        private const int READ_CONTROL = 0x00020000;
        private const int WRITE_DAC = 0x00040000;
        private const int WRITE_OWNER = 0x00080000;
        private const int SYNCHRONIZE = 0x00100000;
        private const int FILE_READ_ATTRIBUTES = 0x00000080;
        private const int FILE_READ_EA = 0x00000008;
        private const int FILE_READ_DATA = 0x00000001;
        private const int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;

        // Kernel api import
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

            // EventLog instance assigned source.
            evLog.Source = SERVICE_NAME;
            evLog.Log = SERVICE_LOG;
        }

        protected override void OnStart(string[] args)
        {
            //this.CanStop = false;
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
                Console.WriteLine("ADService: driver not installed.");
                evLog.WriteEntry("ADService: driver not installed.");
                throw new Exception();
            }

            mFilter.OnBeforeReadFile += OnBeforeReadFile;
            mFilter.OnBeforeRenameOrMoveFile += OnBeforeRenameOrMoveFile;
            //mFilter.OnBeforeWriteFile += OnBeforeWriteFile;
            //mFilter.OnAfterWriteFile += OnAfterWriteFile;
            //mFilter.OnAfterCloseFile += OnAfterCloseFile;
            mFilter.OnNotifyCloseFile += OnNotifyCloseFile;
            long adFS = Constants.FS_CE_BEFORE_RENAME | Constants.FS_CE_BEFORE_READ;
            //long genericFS = Constants.FS_CE_BEFORE_WRITE;
            //long genericFS = Constants.FS_CE_AFTER_WRITE | Constants.FS_CE_AFTER_CLOSE;
            long closeFS = Constants.FS_NE_CLOSE;
            mFilter.AddFilterRule("*" + ACTIVEDATA_EXTENSION, Constants.ACCESS_NONE, adFS, Constants.FS_NE_NONE);
            mFilter.AddFilterRule("*" + ADLIST_EXTENSION, Constants.ACCESS_NONE, adFS, Constants.FS_NE_NONE);
            mFilter.AddFilterRule("*.*", Constants.ACCESS_NONE, Constants.FS_CE_NONE, closeFS);

            mFilter.Initialize(mGuid);
            mFilter.ProcessCachedIORequests = true;
            //mFilter.Config("AllowFileAccessInBeforeOpen=false;ModifiableReadWriteBuffers=true");
            mFilter.Config("AllowFileAccessInBeforeOpen=false");
            mFilter.StartFilter(5000);
            mFilter.FileFlushingBehavior = 0;

            loadProcessedFile();

            evLog.WriteEntry("Service started. " + driveStatus + " Active:" + mFilter.Active);
            Console.WriteLine("Service started. " + driveStatus + " Active:" + mFilter.Active);
        }

        protected override void OnStop()
        {
            try
            {
                mFilter.StopFilter(false);
                mFilter.Dispose();
                updateProcessedFile();
                Console.WriteLine("ADService: Service stopped.");
                evLog.WriteEntry("ADService: Service stopped.");                
                evLog.Dispose();
            }
            catch (CBFSFilterException err)
            {
                Console.WriteLine("ADService: Stop error: " + err.Message);
                evLog.WriteEntry("ADService: Stop error: " + err.Message);
            }
        }

        protected override void OnShutdown()
        {
            Console.WriteLine("ADService: System shutdown, stopping.");
            evLog.WriteEntry("ADService: System shutdown, stopping.");
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

            if (isAdListFile(fname))
            {
                Console.WriteLine("Process " + process + " tried to open adlist file. Request blocked.");
                evLog.WriteEntry("Process " + process + " tried to open adlist file. Request blocked.");
                e.ProcessRequest = false;
                e.ResultCode = ERROR_ACCESS_DENIED;
            }
        }

        /*
         * Handle the process of renaming file.
         * 
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

            // The adlist file is only allowed by driver
            if (isAdListFile(fname))
            {
                e.ProcessRequest = false;
                e.ResultCode = ERROR_ACCESS_DENIED;
                Console.WriteLine("Process " + process + " tried to rename/move adlist file. Request blocked.");
                evLog.WriteEntry("Process " + process + " tried to rename/move adlist file. Request blocked.");

                return;
            }

            // is the user trying to rename only filename? (excluding extension)
            if (isActiveDataFileName(newfname))
            {
                // no...block!
                e.ProcessRequest = true;
                e.ResultCode = 0;
                Console.WriteLine("Process " + process + " tried to rename/move adlist file " + fname + " to " + newfname + ". Request allowed.");
                evLog.WriteEntry("Process " + process + " tried to rename/move adlist file " + fname + " to " + newfname + ". Request allowed.");
            }
            else
            {
                // yes...allow!
                e.ProcessRequest = false;
                e.ResultCode = ERROR_ACCESS_DENIED;
                Console.WriteLine("Process " + process + " tried to rename/move adlist file " + fname + " to " + newfname + ". Request blocked.");
                evLog.WriteEntry("Process " + process + " tried to rename/move adlist file " + fname + " to " + newfname + ". Request blocked.");
            }
        }

        /*
         * The BeforeRead event is applied only to activedata/adlist files
         * - If the file is adlist then the driver will block ANY access. The driver is the only
         *   process allowed to interact with this file
         * 
         * - If the file is and activedata then it scans for the header data (file must be at least
         *   2048 bytes long) and check for magic words. If ok then check which process is trying
         *   to read the data. Actually only ADEDITOR, registered browsers and mail client are allowed
         *   to read the file (last two for attachment purposes).
         *
         */
        private void OnBeforeReadFile(object Sender, CbfilterBeforeReadFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();
            
            // The adlist file is only allowed by driver, any other process cannot read it
            if (isAdListFile(fname))
            {                
                e.ProcessRequest = false;
                e.ResultCode = ERROR_ACCESS_DENIED;
                Console.WriteLine("Process " + process + " tried to read adlist file. Request blocked.");
                evLog.WriteEntry("Process " + process + " tried to read adlist file. Request blocked.");

                return;
            }

            // some error may occur...
            int errorCode;
            byte[] adBuff = readActiveDataHeader(fname, out errorCode);
            if (errorCode == 0)
            {
                ActiveDataFile adf = ByteArrayToActiveData(adBuff);

                // check if the file is an activedata "magic word" (maybe a though check is needed...)
                if (baToStringNull(adf.magic) != "*AD*")
                {                                        
                    e.ProcessRequest = false;
                    e.ResultCode = ERROR_BAD_FORMAT;
                    Console.WriteLine("Reading of file {0} failed. It's not an activedata.", fname);
                    evLog.WriteEntry("Reading of file " + fname + " failed. It's not an activedata.");

                    return;
                }

                // ok, so the file is an active data, is the activedata editor opening it?
                if(isAdProcess(process))
                {
                    // Yes, perform checks and execute onRead event
                    Console.WriteLine("Reading of file {0} by AdEditor...exec onRead", fname);
                }

                // not active data editor? So check for mail/browser app
                if (isAllowedApp(process))
                {
                    // Yes, perform checks and execute onRead event
                    Console.WriteLine("Reading of file {0} by {1}...exec onShare", fname, process);
                }
            }
            else
            {
                e.ProcessRequest = false;
                e.ResultCode = errorCode;
                Console.WriteLine("Reading of file {0} failed. Blocking further processing. Error code: "+errorCode);
                evLog.WriteEntry("Reading of file {0} failed. Blocking further processing. Error code: " + errorCode);

                return;
            }
               
            // *********************** CODE USED TO UPDATE FILE *********************************
               // UInt64 n = 0; 
               // IntPtr ptr = new IntPtr((int)n);
               // SetFilePointerEx((IntPtr)fHandler, -buff.Length, IntPtr.Zero, 1); //FILE_BEGIN = 0, FILE_POSITION = 1

               // var natOverlap3 = new NativeOverlapped { OffsetLow = (int)0 };
               // WriteFile((IntPtr)fHandler, buff, 2048, out buffWritten, ref natOverlap3);                                           
        }

        /*
         * Then NotifyClose event is called just after the file have been closed.
         * It opens the file, check if size is >=2048 bytes and after that checks
         * a possible activedata header. If so, it checks the filename to see
         * if some process is trying to save an actual activedata into another filename
         * with different extension ("Save As...") just to bypass any further control.
         * If so, the service/driver rename the file into .activedata extension
         * This check is performed only if a file is coming from browsers or mail
         * client (download attachment). If the process is the activedata editor nothing
         * is done.
         */
        private void OnNotifyCloseFile(object Sender, CbfilterNotifyCloseFileEventArgs e)
        {
            string process = mFilter.GetOriginatorProcessName().ToUpper();
            string fname = e.FileName.ToUpper();

            // An allowed app is trying to save something not (possibily?) .activedata?
            if (isAllowedApp(process) && !isActiveDataFileName(fname))
            {
                int errorCode;
                long fSize = getFileSize(fname, out errorCode);
                if(errorCode!=0)
                {
                    e.ResultCode = errorCode;
                    Console.WriteLine("Getting size of file {0} failed after close. Error code: " + errorCode);
                    evLog.WriteEntry("Getting size of file {0} failed after close. Error code: " + errorCode);

                    return;
                }

                // not enough bytes...surely is not an activedata!
                if (fSize < 2048) return;

                // Read header of file                
                byte[] baBuff = readActiveDataHeader(fname, out errorCode);
                if(errorCode!=0)
                {
                    e.ResultCode = errorCode;
                    Console.WriteLine("Reading of file {0} failed after close. Error code: " + errorCode);
                    evLog.WriteEntry("Reading of file {0} failed after close. Error code: " + errorCode);

                    return;
                }

                ActiveDataFile adf = ByteArrayToActiveData(baBuff);
                string magic = Encoding.UTF8.GetString(adf.magic);
                string magic2 = Encoding.UTF8.GetString(adf.magic2);
                // Is it an active data file?
                if (magic == "*AD*" && magic2 == "DF")
                {
                    // Compute hash to see if file was already saved
                    string hash = computeFileHash(fname, out errorCode);
                    if(errorCode!=0)
                    {
                        e.ResultCode = errorCode;
                        Console.WriteLine("Computing hash of file {0} failed after close. Deleting. Error code: " + errorCode);
                        evLog.WriteEntry("Computing hash of file {0} failed after close. Deleting. Error code: " + errorCode);

                        File.Delete(fname);

                        return;
                    }

                    // Was the file saved before?
                    if(isAlreadyProcessed(hash))
                    {                        
                        Console.WriteLine("File {0} was previously saved. Deleting.");
                        evLog.WriteEntry("File {0} was previously saved. Deleting.");

                        File.Delete(fname);

                        return;
                    }

                    // Yes...trying to gable? Rename the file!
                    string newFname = Path.ChangeExtension(e.FileName, ".ActiveData");
                    System.IO.File.Move(e.FileName, newFname);
                    // update list of processed files
                    alreadyProcessed.Add(hash);

                    Console.WriteLine("Process "+process+" tried to save an activedata with filename "+fname+". Renaming completed.");
                    evLog.WriteEntry("Process " + process + " tried to save an activedata with filename " + fname + ". Renaming completed.");
                }
            }
        }
        
        // HELPER FUNCTIONS...TO BE CLEARED!
        private byte[] readActiveDataHeader(string fname, out int errorCode)
        {
            errorCode = 0;
            try
            {
                // Open the file bypassing filter stack...directly to kernel (parameters MUST be fixed later!)
                long fHandler = mFilter.CreateFileDirect(fname, false, FILE_READ_DATA, 3, 128, false);
                if (fHandler == 0)
                {
                    errorCode = ERROR_INVALID_HANDLE;
                    return null;
                }

                // Get the size of the file and check if the file is at least 2048 bytes long (the minimum size of activedata file)
                long fsize = 0;
                bool result = GetFileSizeEx((IntPtr)fHandler, out fsize);
                if (!result || fsize < 2048)
                {
                    CloseHandle((IntPtr)fHandler);
                    errorCode = (fsize < 2048) ? ERROR_BAD_FORMAT : ERROR_INVALID_HANDLE;
                    return null;
                }

                // Read the first 2048 bytes and them map them to header format
                byte[] buff = new byte[2048];
                uint buffRead;
                ReadFile((IntPtr)fHandler, buff, 2048, out buffRead, IntPtr.Zero);
                CloseHandle((IntPtr)fHandler);
                
                if(buffRead!=buff.Length)
                {
                    errorCode = ERROR_BAD_FORMAT;
                    return null;
                }

                int bSize = Marshal.SizeOf(new ActiveDataFile());
                byte[] adBuff = new byte[bSize];
                for (int i = 0; i < adBuff.Length; ++i) adBuff[i] = buff[i];
                
                return adBuff;
            }
            catch (CBFSFilterCbfilterException ex)
            {                
                errorCode = ex.Code;
                return null;
            }
        }

        private long getFileSize(string fname, out int errorCode)
        {
            errorCode = 0;
            try
            {
                // Open the file bypassing filter stack...directly to kernel (parameters MUST be fixed later!)
                long fHandler = mFilter.CreateFileDirect(fname, false, FILE_READ_DATA, 3, 128, false);
                if (fHandler == 0)
                {
                    errorCode = ERROR_INVALID_HANDLE;
                    return 0;
                }

                // Get the size of the file and check if the file is at least 2048 bytes long (the minimum size of activedata file)
                long fsize = 0;
                bool result = GetFileSizeEx((IntPtr)fHandler, out fsize);
                CloseHandle((IntPtr)fHandler);
                if (!result)
                {                    
                    errorCode = ERROR_INVALID_HANDLE;
                    return 0;
                }
                
                return fsize;
            }
            catch (CBFSFilterCbfilterException ex)
            {                
                errorCode = ex.Code;
                return 0;
            }
        }

        private string computeFileHash(string filename, out int errorCode)
        {
            errorCode = 0;
            try
            {
                // Open the file bypassing filter stack...directly to kernel (parameters MUST be fixed later!)
                long fHandler = mFilter.CreateFileDirect(filename, false, FILE_READ_DATA, 3, 128, false);
                if (fHandler == 0)
                {
                    errorCode = ERROR_INVALID_HANDLE;
                    return null;
                }

                // Get the size of the file and check if the file is at least 2048 bytes long (the minimum size of activedata file)
                long fsize = 0;
                bool result = GetFileSizeEx((IntPtr)fHandler, out fsize);
                if (!result)
                {
                    CloseHandle((IntPtr)fHandler);
                    errorCode = ERROR_INVALID_HANDLE;
                    return null;
                }

                // Read the first 2048 bytes and them map them to header format
                byte[] buff = new byte[fsize];
                uint buffRead;
                ReadFile((IntPtr)fHandler, buff, (uint)buff.Length, out buffRead, IntPtr.Zero);
                CloseHandle((IntPtr)fHandler);

                if (buffRead != buff.Length)
                {
                    errorCode = ERROR_BAD_FORMAT;
                    return null;
                }

                byte[] hash = sha1.ComputeHash(buff);
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)                
                    sb.Append(b.ToString("X2"));

                return sb.ToString();
            }
            catch (CBFSFilterCbfilterException ex)
            {                
                errorCode = ex.Code;
                return null;
            }
        }

        private bool isAdProcess(string process)
        {
            if (process.EndsWith("ADEDITOR.EXE"))
            {
                // compute file hash to verify origin of app
                int errorCode;
                string hash = computeFileHash(process, out errorCode);
                if(errorCode==0 && hash==ADEDITOR_HASH) 
                    return true;
            }

            return false;
        }

        private bool isAdListFile(string filename)
        {
            return filename.ToUpper().EndsWith(ADLIST_EXTENSION);
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

        private bool isAlreadyProcessed(string toLook)
        {
            return alreadyProcessed.Contains(toLook);
        }

        private void loadProcessedFile()
        {
            try
            {
                alreadyProcessed = new List<string>(File.ReadAllLines(ADLIST_FILE));

                Console.WriteLine(ADLIST_FILE + " loaded. Currently known files: "+alreadyProcessed.Count);
                evLog.WriteEntry(ADLIST_FILE + " loaded. Currently known files: " + alreadyProcessed.Count);
            }
            catch(FileNotFoundException)
            {
                alreadyProcessed.Clear();

                Console.WriteLine(ADLIST_FILE+" does not exits. Clearing and starting from scratch.");
                evLog.WriteEntry(ADLIST_FILE + " does not exits. Clearing and starting from scratch.");
            }
        }

        private void updateProcessedFile()
        {
            using (StreamWriter sw = File.CreateText(ADLIST_FILE))
            {
                foreach (string l in alreadyProcessed)
                    sw.WriteLine(l);
            }
        }

        private bool isActiveDataFileName(string filename)
        {
            return filename.ToUpper().EndsWith(ACTIVEDATA_EXTENSION);
        }        

        private bool isAllowedApp(string process)
        {
            var mc = PlatformMail.getInstalledMailClients();
            var bc = PlatformBrowser.GetInstalledBrowsers();
            for (var i = 0; i < bc.Count; i++)
            {
                if (bc[i].ExecutablePath.ToUpper() == process) return true;
            }
            for (var i = 0; i < mc.Length; i++)
            {
                if (mc[i].ExecutablePath.ToUpper() == process) return true;
            }
            return false;
        }
    }
}
