// Independent Windows NTDLL observations; no RAX assembly or library is used.
// Unmanaged allocations keep all kernel-visible pointers stable across GC.
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class NativeNameReference
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Version
    {
        public uint Size;
        public uint Major;
        public uint Minor;
        public uint Build;
        public uint Platform;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ServicePack;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int RtlGetVersion(ref Version version);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtQueryInformationFile(
        IntPtr file, IntPtr io, IntPtr output, uint length, int informationClass);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetSystemDirectoryW(StringBuilder output, uint length);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetOverlappedResult(
        IntPtr handle, IntPtr overlapped, out uint bytes, bool wait);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process2(
        IntPtr process, out ushort processMachine, out ushort nativeMachine);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessMachineInformation
    {
        public ushort ProcessMachine;
        public ushort Reserved;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessInformation(IntPtr process, int informationClass,
        out ProcessMachineInformation information, uint bytes);

    private static string Hex(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    private static byte[] Read(IntPtr address, int bytes)
    {
        byte[] result = new byte[bytes];
        Marshal.Copy(address, result, 0, bytes);
        return result;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }

    private static ulong Information(IntPtr io)
    {
        return IntPtr.Size == 8
            ? unchecked((ulong)Marshal.ReadInt64(io, IntPtr.Size))
            : unchecked((uint)Marshal.ReadInt32(io, IntPtr.Size));
    }

    [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string source, string target, uint flags);

    private static int Main()
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        ProcessMachineInformation machine;
        Require(GetProcessInformation(GetCurrentProcess(), 9, out machine, 8), "process machine");
        Console.WriteLine("{\"kind\":\"host\",\"machine\":" + machine.ProcessMachine + "}");
        for (int mode = 0; mode < 4; ++mode)
        {
            string root = System.IO.Path.Combine(Environment.CurrentDirectory, "root-move-" + mode);
            string moved = root + "-moved";
            string nested = System.IO.Path.Combine(root, "nested");
            string name = System.IO.Path.Combine(nested, "file.txt");
            Require(!System.IO.Directory.Exists(root) && !System.IO.Directory.Exists(moved), "preserve existing fixture");
            System.IO.Directory.CreateDirectory(nested);
            System.IO.File.WriteAllText(System.IO.Path.Combine(root, ".owner"), "native-root-move-v1");
            System.IO.File.WriteAllText(name, "owned child");
            IntPtr file = new IntPtr(-1), parent = new IntPtr(-1), child = new IntPtr(-1);
            bool success = false;
            try
            {
                if (mode == 1 || mode == 2)
                {
                    file = CreateFileW(name, 0, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                    Require(file != new IntPtr(-1), "metadata file open");
                }
                if (mode == 2 || mode == 3)
                {
                    parent = CreateFileW(root, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
                    child = CreateFileW(nested, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
                    Require(parent != new IntPtr(-1) && child != new IntPtr(-1), "metadata directory open");
                }
                success = MoveFileExW(root, moved, 1);
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("{\"kind\":\"move\",\"mode\":" + mode
                    + ",\"file_handle\":" + ((mode == 1 || mode == 2) ? "true" : "false")
                    + ",\"root_handles\":" + ((mode == 2 || mode == 3) ? "true" : "false")
                    + ",\"success\":" + (success ? "true" : "false") + ",\"last_error\":" + error + "}");
            }
            finally
            {
                foreach (IntPtr handle in new IntPtr[] { file, parent, child })
                    if (handle != new IntPtr(-1)) Require(CloseHandle(handle), "owned close");
            }
            string actual = success ? moved : root;
            Require(System.IO.File.ReadAllText(System.IO.Path.Combine(actual, ".owner")) == "native-root-move-v1", "ownership");
            System.IO.Directory.Delete(actual, true);
        }
        Console.WriteLine("{\"kind\":\"complete\",\"moves\":4,\"owned_fixtures_removed\":true}");
        return 0;
    }

    private static byte[] Subarray(byte[] source, int count)
    {
        byte[] result = new byte[count];
        Buffer.BlockCopy(source, 0, result, 0, count);
        return result;
    }
}
