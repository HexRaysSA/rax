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

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr file, StringBuilder output, uint characters, uint flags);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string name, string existing, IntPtr security);

    private static void Observe(IntPtr file, string stage, uint access)
    {
        int ioBytes = 3 * IntPtr.Size + 8;
        IntPtr io = Marshal.AllocHGlobal(ioBytes);
        IntPtr data = Marshal.AllocHGlobal(2080);
        try
        {
            byte[] initialIo = new byte[ioBytes];
            for (int i = 0; i < 2 * IntPtr.Size; ++i) initialIo[i] = 0xa5;
            initialIo[0] = 3;
            initialIo[1] = 1;
            initialIo[2] = initialIo[3] = 0;
            Marshal.Copy(initialIo, 0, io, initialIo.Length);
            byte[] initial = new byte[2080];
            for (int i = 0; i < initial.Length; ++i) initial[i] = 0xa5;
            Marshal.Copy(initial, 0, data, initial.Length);
            uint returned = unchecked((uint)NtQueryInformationFile(
                file, io, IntPtr.Add(data, 16), 2048, 9));
            if (returned == 0x103)
            {
                for (;;)
                {
                    uint transferred;
                    bool terminal = GetOverlappedResult(file, io, out transferred, false);
                    int error = Marshal.GetLastWin32Error();
                    if (terminal || (error != 996
                        && unchecked((uint)Marshal.ReadInt32(io)) != 0x103)) break;
                    Thread.Sleep(1);
                }
            }
            uint completed = returned == 0x103
                ? unchecked((uint)Marshal.ReadInt32(io)) : returned;
            byte[] result = Read(data, 2080);
            for (int i = 0; i < 16; ++i)
            {
                Require(result[i] == 0xa5, "native prefix sentinel changed");
                Require(result[2064 + i] == 0xa5, "native tail sentinel changed");
            }
            Console.WriteLine("{\"kind\":\"query\",\"stage\":\"" + stage
                + "\",\"access\":" + access + ",\"returned\":" + returned
                + ",\"completed\":" + completed
                + ",\"iosb_hex\":\"" + Hex(Read(io, 2 * IntPtr.Size))
                + "\",\"output_hex\":\"" + Hex(result) + "\"}");
        }
        finally
        {
            // Every pending request is observed to completion before release.
            Marshal.FreeHGlobal(data);
            Marshal.FreeHGlobal(io);
        }
        foreach (uint flags in new uint[] { 0, 8 })
        {
            StringBuilder name = new StringBuilder(32768);
            uint count = GetFinalPathNameByHandleW(file, name, (uint)name.Capacity, flags);
            int error = Marshal.GetLastWin32Error();
            Require(count < name.Capacity, "native fixture path exceeded private capacity");
            Console.WriteLine("{\"kind\":\"final_path\",\"stage\":\"" + stage
                + "\",\"access\":" + access + ",\"flags\":" + flags
                + ",\"returned_characters\":" + count + ",\"error\":" + error
                + ",\"name_hex\":\"" + Hex(Encoding.Unicode.GetBytes(name.ToString())) + "\"}");
        }
    }

    private static int Main()
    {
        Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
        Console.OutputEncoding = new UTF8Encoding(false);
        ProcessMachineInformation machine;
        Require(GetProcessInformation(GetCurrentProcess(), 9, out machine, 8),
            "cannot identify associated process machine");
        Version version = new Version();
        version.Size = (uint)Marshal.SizeOf(typeof(Version));
        version.ServicePack = "";
        Require(RtlGetVersion(ref version) == 0, "native version query failed");
        Console.WriteLine("{\"kind\":\"host\",\"machine\":" + machine.ProcessMachine
            + ",\"pointer_bytes\":" + IntPtr.Size + ",\"build\":" + version.Build + "}");
        string root = System.IO.Path.Combine(Environment.CurrentDirectory, "lifetime-fixture-v1");
        Require(!System.IO.Directory.Exists(root), "preserve existing lifetime fixture");
        System.IO.Directory.CreateDirectory(root);
        string owner = System.IO.Path.Combine(root, ".owner");
        System.IO.File.WriteAllText(owner, "native-file-name-lifetime-v1");
        int queries = 0;
        foreach (uint access in new uint[] { 0, 0x80, 0x80000000 })
        {
            string prefix = access.ToString("x8", CultureInfo.InvariantCulture);
            string original = System.IO.Path.Combine(root, prefix + "-name-\u03bb-\ud83d\udd39.txt");
            string renamed = System.IO.Path.Combine(root, prefix + "-renamed-\u03bb-\ud83d\udd39.txt");
            string alias = System.IO.Path.Combine(root, prefix + "-alias-\u03bb-\ud83d\udd39.txt");
            System.IO.File.WriteAllText(original, "owned native name identity");
            IntPtr file = CreateFileW(original, access, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            if (file == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr aliasFile = new IntPtr(-1);
            try
            {
                Console.WriteLine("{\"kind\":\"fixture\",\"access\":" + access
                    + ",\"original_hex\":\"" + Hex(Encoding.Unicode.GetBytes(original))
                    + "\",\"renamed_hex\":\"" + Hex(Encoding.Unicode.GetBytes(renamed))
                    + "\",\"alias_hex\":\"" + Hex(Encoding.Unicode.GetBytes(alias)) + "\"}");
                Observe(file, "initial", access); ++queries;
                System.IO.File.Move(original, renamed);
                Observe(file, "renamed", access); ++queries;
                System.IO.File.WriteAllText(original, "replacement identity");
                Observe(file, "replaced", access); ++queries;
                Require(CreateHardLinkW(alias, renamed, IntPtr.Zero), "owned native hard link failed");
                aliasFile = CreateFileW(alias, access, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                if (aliasFile == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
                Observe(file, "original_after_alias_open", access); ++queries;
                Observe(aliasFile, "alias_open", access); ++queries;
                System.IO.File.Delete(renamed);
                Observe(file, "original_after_primary_delete", access); ++queries;
                Observe(aliasFile, "alias_after_primary_delete", access); ++queries;
                System.IO.File.Delete(alias);
                Observe(file, "original_after_alias_delete", access); ++queries;
                Observe(aliasFile, "alias_after_alias_delete", access); ++queries;
            }
            finally
            {
                if (aliasFile != new IntPtr(-1)) Require(CloseHandle(aliasFile), "alias close failed");
                Require(CloseHandle(file), "original close failed");
            }
            System.IO.File.Delete(original);
            System.IO.File.Delete(renamed);
            System.IO.File.Delete(alias);
        }
        Require(queries == 27, "incomplete native lifetime matrix");
        Require(System.IO.File.ReadAllText(owner) == "native-file-name-lifetime-v1", "fixture ownership");
        System.IO.File.Delete(owner);
        System.IO.Directory.Delete(root);
        Console.WriteLine("{\"kind\":\"complete\",\"queries\":" + queries
            + ",\"final_path_observations\":54,\"owned_fixture_removed\":true,\"skipped\":0}");
        return 0;
    }

    private static byte[] Subarray(byte[] source, int count)
    {
        byte[] result = new byte[count];
        Buffer.BlockCopy(source, 0, result, 0, count);
        return result;
    }
}
