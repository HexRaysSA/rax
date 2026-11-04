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

    private static int Main()
    {
        Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
        Console.OutputEncoding = new UTF8Encoding(false);
        ushort processMachine;
        ushort nativeMachine;
        Require(IsWow64Process2(GetCurrentProcess(), out processMachine, out nativeMachine),
            "cannot identify native caller ABI");
        ushort machine = processMachine == 0 ? nativeMachine : processMachine;
        Version version = new Version();
        version.Size = (uint)Marshal.SizeOf(typeof(Version));
        version.ServicePack = "";
        Require(RtlGetVersion(ref version) == 0, "native version query failed");
        Console.WriteLine("{\"kind\":\"host\",\"machine\":" + machine
            + ",\"process_machine\":" + processMachine
            + ",\"native_machine\":" + nativeMachine
            + ",\"pointer_bytes\":" + IntPtr.Size
            + ",\"major\":" + version.Major + ",\"minor\":" + version.Minor
            + ",\"build\":" + version.Build + ",\"managed_caller\":true}");

        StringBuilder system = new StringBuilder(32768);
        uint count = GetSystemDirectoryW(system, (uint)system.Capacity);
        Require(count > 0 && count < system.Capacity, "system directory query failed");
        string[] paths = { system.ToString(), System.IO.Path.Combine(system.ToString(), "ntdll.dll") };
        string[] labels = { "directory", "file" };
        uint[] lengths = { 0, 1, 3, 4, 5, 7, 8, 9, 10, 11, 12, 15,
            16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1024 };
        int[] offsets = { 0, 1, 2, 3, 4, 7, 8 };
        uint[] requests = { 0, 0x80, 0x80000000 };
        int cases = 0;
        int successes = 0;
        int pending = 0;
        for (int objectIndex = 0; objectIndex < paths.Length; ++objectIndex)
        {
            string label = labels[objectIndex];
            Console.WriteLine("{\"kind\":\"input\",\"object\":\"" + label
                + "\",\"name_hex\":\"" + Hex(Encoding.Unicode.GetBytes(paths[objectIndex])) + "\"}");
            foreach (bool asynchronous in new bool[] { false, true })
            {
                foreach (uint request in requests)
                {
                    uint access = asynchronous ? request | 0x00100000 : request;
                    uint flags = (objectIndex == 0 ? 0x02000080u : 0x80u)
                        | (asynchronous ? 0x40000000u : 0);
                    IntPtr handle = CreateFileW(paths[objectIndex], access, 7,
                        IntPtr.Zero, 3, flags, IntPtr.Zero);
                    if (handle == new IntPtr(-1))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "read-only native open");
                    try
                    {
                        int handleSuccesses = 0;
                        foreach (uint length in lengths)
                        {
                            foreach (int offset in offsets)
                            {
                                // OVERLAPPED begins with the native IOSB. The extra
                                // fields make GetOverlappedResult observation valid.
                                int ioBytes = 3 * IntPtr.Size + 8;
                                IntPtr io = Marshal.AllocHGlobal(ioBytes);
                                IntPtr buffer = Marshal.AllocHGlobal(4096);
                                try
                                {
                                    byte[] initialIo = new byte[ioBytes];
                                    for (int i = 0; i < 2 * IntPtr.Size; ++i)
                                        initialIo[i] = 0xa5;
                                    initialIo[0] = 3;
                                    initialIo[1] = 1;
                                    initialIo[2] = 0;
                                    initialIo[3] = 0;
                                    Marshal.Copy(initialIo, 0, io, initialIo.Length);
                                    byte[] initial = new byte[4096];
                                    for (int i = 0; i < initial.Length; ++i)
                                        initial[i] = 0xa5;
                                    Marshal.Copy(initial, 0, buffer, initial.Length);
                                    int start = 16 + offset;
                                    int captured = start + (int)length + 16;
                                    Require(captured <= initial.Length, "private output span");
                                    uint returned = unchecked((uint)NtQueryInformationFile(
                                        handle, io, IntPtr.Add(buffer, start), length, 9));
                                    if (returned == 0x103)
                                    {
                                        ++pending;
                                        for (;;)
                                        {
                                            uint transferred;
                                            bool completed = GetOverlappedResult(handle, io, out transferred, false);
                                            int error = Marshal.GetLastWin32Error();
                                            if (completed || (error != 996
                                                && unchecked((uint)Marshal.ReadInt32(io)) != 0x103))
                                                break;
                                            // A timeout/error never releases owners
                                            // while the IOSB can still be pending.
                                            Thread.Sleep(1);
                                        }
                                    }
                                    uint status = returned == 0x103
                                        ? unchecked((uint)Marshal.ReadInt32(io)) : returned;
                                    byte[] output = Read(buffer, captured);
                                    for (int i = 0; i < start; ++i)
                                        Require(output[i] == 0xa5, "prefix sentinel changed");
                                    for (int i = start + (int)length; i < captured; ++i)
                                        Require(output[i] == 0xa5, "tail sentinel changed");
                                    if (status == 0)
                                    {
                                        ulong information = Information(io);
                                        Require(information >= 4 && information <= length, "successful native bytes");
                                        ++handleSuccesses;
                                        ++successes;
                                    }
                                    ++cases;
                                    Console.WriteLine("{\"kind\":\"query\",\"object\":\"" + label
                                        + "\",\"asynchronous\":" + (asynchronous ? "true" : "false")
                                        + ",\"access\":" + access + ",\"length\":" + length
                                        + ",\"offset\":" + offset + ",\"returned\":" + returned
                                        + ",\"completed\":" + status
                                        + ",\"initial_iosb_hex\":\"" + Hex(Subarray(initialIo, 2 * IntPtr.Size))
                                        + "\",\"iosb_hex\":\"" + Hex(Read(io, 2 * IntPtr.Size))
                                        + "\",\"output_hex\":\"" + Hex(output) + "\"}");
                                }
                                finally
                                {
                                    // Only a terminal native return/observation
                                    // reaches here; no buffer moves during GC.
                                    Marshal.FreeHGlobal(buffer);
                                    Marshal.FreeHGlobal(io);
                                }
                            }
                        }
                        Require(handleSuccesses > 0, "no successful class 9 queries for handle");
                    }
                    finally
                    {
                        Require(CloseHandle(handle), "private native close failed");
                    }
                }
            }
        }
        Require(cases == 2016, "native matrix was incomplete");
        Console.WriteLine("{\"kind\":\"complete\",\"queries\":" + cases
            + ",\"successes\":" + successes + ",\"pending\":" + pending + ",\"skipped\":0}");
        return 0;
    }

    private static byte[] Subarray(byte[] source, int count)
    {
        byte[] result = new byte[count];
        Buffer.BlockCopy(source, 0, result, 0, count);
        return result;
    }
}
