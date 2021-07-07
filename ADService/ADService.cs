using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using System.IO;
using callback.CBFSFilter;
using adEditor;
using System.Security.Cryptography;
using System.IO.Pipes;
using System.Security.Principal;

namespace ADService
{
    public partial class ADService : ServiceBase
    {
        // Filter object and GUID
        private readonly Cbfilter mFilter = new Cbfilter();        
        private const string mGuid = "{713CC6CE-B3E2-4FD9-838D-E28F558F6866}";
        // Logging event viewer parameters
        private readonly EventLog evLog = new EventLog();
        private const string SERVICE_NAME = "ADService";
        private const string SERVICE_LOG = "Application";
        // SHA1 hashing object
        private readonly SHA1Managed sha1 = new SHA1Managed();
        // Error codes
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_HANDLE = 6;
        private const int ERROR_BAD_FORMAT = 11;
        private const uint ERROR_PRIVILEGE_NOT_HELD = 1314;
        private const uint ERROR_AD_EXPIRED = 0xA007052E;                
        // Useful constants        
        private const string ACTIVEDATA_EXTENSION = ".ACTIVEDATA";
        private const string ADEDITOR_HASH = "D1548905DB6D8FEEFC8CBFA729030B5F50BAF823";
        // File access constants (fileapi.h CreateFileA/W)
        private const int DELETE = 0x00010000;
        private const int READ_CONTROL = 0x00020000;
        private const int WRITE_DAC = 0x00040000;
        private const int WRITE_OWNER = 0x00080000;
        private const int SYNCHRONIZE = 0x00100000;
        private const int FILE_READ_ATTRIBUTES = 0x00000080;
        private const int FILE_READ_EA = 0x00000008;
        private const int FILE_READ_DATA = 0x00000001;
        private const int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const int FILE_WRITE_DATA = 0x00000002;
        // dwCreationDisposition (fileapi.h CreateFileA/W)
        private const int CREATE_NEW = 1;
        private const int CREATE_ALWAYS = 2;
        private const int OPEN_EXISTING = 3;
        private const int OPEN_ALWAYS = 4;
        private const int TRUNCATE_EXISTING = 5;
        // dwFlagsAndAttributes (fileapi.h CreateFileA/W)
        private const uint FILE_ATTRIBUTE_ARCHIVE = 0x20;
        private const uint FILE_ATTRIBUTE_ENCRYPTED = 0x4000;
        private const uint FILE_ATTRIBUTE_HIDDEN = 0x2;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint FILE_ATTRIBUTE_OFFLINE = 0x1000;
        private const uint FILE_ATTRIBUTE_READONLY = 0x1;
        private const uint FILE_ATTRIBUTE_SYSTEM = 0x4;
        private const uint FILE_ATTRIBUTE_TEMPORARY = 0x100;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
        private const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
        private const uint FILE_FLAG_OPEN_NO_RECALL = 0x00100000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const uint FILE_FLAG_POSIX_SEMANTICS = 0x01000000;
        private const uint FILE_FLAG_RANDOM_ACCESS = 0x10000000;
        private const uint FILE_FLAG_SESSION_AWARE = 0x00800000;
        private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
        private const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;

        // Kernel api import
/*        [DllImport("kernel32.dll")]
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
*/

        /*
         * Constructor
         */
        public ADService()
        {
            InitializeComponent();

            ((ISupportInitialize)(this.EventLog)).BeginInit();
            if (!EventLog.SourceExists(SERVICE_NAME))
            {                
                EventLog.CreateEventSource(SERVICE_NAME, SERVICE_LOG);
            }
            ((ISupportInitialize)(this.EventLog)).EndInit();

            // EventLog instance assigned source.
            evLog.Source = SERVICE_NAME;
            evLog.Log = SERVICE_LOG;
        }

        /*
         * Called when the service is being started
         */
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

            // Rename and Read are applied only to activedata
            long fsFlags = Constants.FS_CE_BEFORE_RENAME | Constants.FS_CE_BEFORE_READ;
            mFilter.OnBeforeReadFile += OnBeforeReadFile;
            mFilter.OnBeforeRenameOrMoveFile += OnBeforeRenameOrMoveFile;
            mFilter.AddFilterRule("*" + ACTIVEDATA_EXTENSION, Constants.ACCESS_NONE, fsFlags, Constants.FS_NE_NONE);            

            mFilter.Initialize(mGuid);
            mFilter.ProcessCachedIORequests = true;
            mFilter.ProcessFailedRequests = false;
            mFilter.Config("AllowFileAccessInBeforeOpen=false");
            mFilter.StartFilter(5000);
            mFilter.FileFlushingBehavior = 0;

            evLog.WriteEntry("Service started. " + driveStatus + " Active:" + mFilter.Active);
            Console.WriteLine("Service started. " + driveStatus + " Active:" + mFilter.Active);           
        }

        /*
         * Called when the service is being stopped
         */
        protected override void OnStop()
        {
            try
            {
                // stop the filter and dispose it
                mFilter.StopFilter(false);
                mFilter.Dispose();
                
                Console.WriteLine("ADService: Service stopped.");
                evLog.WriteEntry("ADService: Service stopped.");                                
            }
            catch (CBFSFilterException err)
            {
                Console.WriteLine("ADService: Stop error: " + err.Message);
                evLog.WriteEntry("ADService: Stop error: " + err.Message);
            }
            // dispose log
            evLog.Dispose();
        }

        /*
         * Called when the service is being stopped during system shutdown
         */
        protected override void OnShutdown()
        {
            Console.WriteLine("ADService: System shutdown, stopping.");
            evLog.WriteEntry("ADService: System shutdown, stopping.");
            //this.CanStop = true;
            //base.OnShutdown();
        }

#if NOSERVICE
        /*
         * Compiled only with NOSERVICE flag enabled, used for debug
         */
        public void _onStart(string[] args)
        {
            OnStart(args);
        }

        /*
         * Compiled only with NOSERVICE flag enabled, used for debug
         */
        public void _onStop()
        {
            OnStop();
        }
#endif
       
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

            // Reset return codes
            e.ProcessRequest = true;
            e.ResultCode = 0;

            // AlternateDataStream (ADS) are allowed
            if (isAlternateDataStream(fname))
            {
                Console.WriteLine("Process "+process+" is allowed to read ADS for file " + fname);
                evLog.WriteEntry("Process " + process + " is allowed to read ADS for file " + fname);
                return;
            }
            
            if(isAdProcess(process))
            {
                ActiveDataFile adf = readActiveDataHeader(e.FileName, out bool ok);
                if (ok)
                {                    
                    // check if the file is an activedata "magic word" (maybe a though check is needed...)
                    if (baToStringNull(adf.magic) != "*AD*" && baToStringNull(adf.magic2) != "DF")
                    {
                        e.ProcessRequest = false;
                        e.ResultCode = ERROR_BAD_FORMAT;
                        Console.WriteLine("Reading of file " + fname + " failed. It's not an activedata.");
                        evLog.WriteEntry("Reading of file " + fname + " failed. It's not an activedata.");

                        return;
                    }
                    else
                    {
                        Console.WriteLine("File " + fname + " IS AN ACTIVEDATA!!!");
                    }
                }
                else
                {
                    e.ProcessRequest = false;
                    e.ResultCode = ERROR_BAD_FORMAT;
                    Console.WriteLine("Reading of activedata header of file " + fname + " failed.");
                    evLog.WriteEntry("Reading of activedata header of file " + fname + " failed.");

                    return;
                }

                // ask to app for key to app (maybe expand code here to interact with desktop app later (eg. errors)
                string pvtKey = askForKey(e.FileName);
                var csp = new RSACryptoServiceProvider(2048);

                //get the object back from the stream
                var privateKey = new RSAParameters();
                privateKey.Exponent = Convert.FromBase64String(pvtKey.Substring(0, 4));
                privateKey.Modulus = Convert.FromBase64String(pvtKey.Substring(4));

                // decrypt header
                var clearHeader = csp.Decrypt(headerbuff, false);
                // decrypt guard header
                // do checks
                // update (eventually) file
            }
            else
            {
                e.ProcessRequest = false;
                e.ResultCode = ERROR_ACCESS_DENIED;
            }                                                                     
        }

        // ***********************************************
        //
        //         HELPER FUNCTIONS...TO BE CLEARED!
        //
        // ***********************************************
        
        private ActiveDataFile readActiveDataHeader(string fname, out bool ok)
        {
            // Open the file bypassing filter stack...directly to kernel (parameters MUST be fixed later!)
            CBFSFilterStream s = mFilter.CreateFileDirectAsStream(fname, false, FILE_READ_DATA, OPEN_EXISTING, (int)FILE_ATTRIBUTE_NORMAL);
            byte[] buffer = new byte[2048].Initialize(0);
            try
            {
                ok = true;                
                long currentPos = s.Position;
                s.Seek(0, SeekOrigin.Begin);
                int actualRead = s.Read(buffer, 0, buffer.Length);
                s.Seek(currentPos, SeekOrigin.Begin);
                s.Close();

                if (actualRead != 2048) ok = false;                                                
            }
            catch(Exception ioe)
            {
                Console.WriteLine("readheader IOE: " + ioe.ToString());
                ok = false;                
            }

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return (ActiveDataFile)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(ActiveDataFile));
            }
            finally
            {
                handle.Free();
            }        
        }

        private bool writeActiveDataHeader(string fname, ActiveDataFile adf)
        {
            // Open the file bypassing filter stack...directly to kernel (parameters MUST be fixed later!)
            CBFSFilterStream s = mFilter.CreateFileDirectAsStream(fname, false, FILE_WRITE_DATA, OPEN_EXISTING, (int)FILE_ATTRIBUTE_NORMAL);
            try
            {
                int length = Marshal.SizeOf(adf);
                IntPtr ptr = Marshal.AllocHGlobal(length);
                byte[] outBuffer = new byte[length];

                Marshal.StructureToPtr(adf, ptr, true);
                Marshal.Copy(ptr, outBuffer, 0, length);
                Marshal.FreeHGlobal(ptr);

                long currentPos = s.Position;
                s.Seek(0, SeekOrigin.Begin);
                s.Write(outBuffer, 0, outBuffer.Length);
                s.Seek(currentPos, SeekOrigin.Begin);
                s.Close();

                return true;
            }
            catch (Exception ioe)
            {
                Console.WriteLine("readheader IOE: " + ioe.ToString());
                return false;
            }            
        }


        private string computeFileHash(string fname)
        {
            try
            {
                using (FileStream fs = new FileStream(@fname, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] hash = sha1.ComputeHash(fs);
                    StringBuilder sb = new StringBuilder(2 * hash.Length);
                    foreach (byte b in hash)
                        sb.Append(b.ToString("X2"));
                    return sb.ToString();
                }
            }
            catch(Exception)
            {
                return null;
            }
        }

        /*
         * Returns true if the process trying to acces file is the adEditor
         */
        private bool isAdProcess(string process)
        {
            if (process.EndsWith("ADEDITOR.EXE"))
            {
                // compute file hash to verify origin of app
                string hash = computeFileHash(process);
                // no error and same hash
                if(hash==ADEDITOR_HASH) 
                    return true;
            }

            return false;
        }        
        
        /*
         * Transform a bytearray to string removing trailing null characters
         */
        private string baToStringNull(byte[] b)
        {
            return Encoding.UTF8.GetString(b).Replace('\0', ' ').Trim();
        }
        
        /*
         * Returns true if the given filename is (possibily) an activedata
         */
        private bool isActiveDataFileName(string filename)
        {
            return filename.ToUpper().EndsWith(ACTIVEDATA_EXTENSION);
        }        

        /*
         * Returns true if the filename is an ADS (Alternate Data Stream)
         */
        private bool isAlternateDataStream(string filename)
        {
            return (filename.ToUpper().EndsWith(".ZONE.IDENTIFIER"));
        }

        private string askForKey(string filename)
        {
            var pipeClient =
                    new NamedPipeClientStream(".", "testpipe",
                        PipeDirection.InOut, PipeOptions.None,
                        TokenImpersonationLevel.Impersonation);
            pipeClient.Connect();

            var ss = new StreamString(pipeClient);
            string key = null;
            // Validate the server's signature string.
            if (ss.ReadString() == "HLO!")
            {
                // The client security token is sent with the first write.
                // Send the name of the file whose contents are returned
                // by the server.
                ss.WriteString(filename);

                // Print the file to the screen.
                key = ss.ReadString();
            }
            else
            
            pipeClient.Close();
            pipeClient.Dispose();

            return key;
        }
    }

    public class StreamString
    {
        private Stream ioStream;
        private UnicodeEncoding streamEncoding;

        public StreamString(Stream ioStream)
        {
            this.ioStream = ioStream;
            streamEncoding = new UnicodeEncoding();
        }

        public string ReadString()
        {
            int len;
            len = ioStream.ReadByte() * 256;
            len += ioStream.ReadByte();
            var inBuffer = new byte[len];
            ioStream.Read(inBuffer, 0, len);

            return streamEncoding.GetString(inBuffer);
        }

        public int WriteString(string outString)
        {
            byte[] outBuffer = streamEncoding.GetBytes(outString);
            int len = outBuffer.Length;
            if (len > UInt16.MaxValue)
            {
                len = (int)UInt16.MaxValue;
            }
            ioStream.WriteByte((byte)(len / 256));
            ioStream.WriteByte((byte)(len & 255));
            ioStream.Write(outBuffer, 0, len);
            ioStream.Flush();

            return outBuffer.Length + 2;
        }
    }

    public class AesCryptographyService
    {
        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, encryptor);
                }
            }
        }

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, decryptor);
                }
            }
        }

        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
    }
}
