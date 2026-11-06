using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class RaxNativeProcessDeviceMapV1
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, uint informationClass,
        IntPtr output, uint length, IntPtr returned);
    [DllImport("ntdll.dll")]
    private static extern int NtWow64QueryInformationProcess64(IntPtr process, uint informationClass,
        IntPtr output, uint length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protection);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint protection, out uint old);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEventW(IntPtr attributes, bool manual, bool initial, IntPtr name);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static string Hex(IntPtr pointer, int length)
    {
        var bytes = new byte[length];
        Marshal.Copy(pointer, bytes, 0, length);
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    public static List<Dictionary<string, object>> Run()
    {
        var rows = new List<Dictionary<string, object>>();
        IntPtr returned = Marshal.AllocHGlobal(4);
        IntPtr buffer = Marshal.AllocHGlobal(128);
        IntPtr evt = CreateEventW(IntPtr.Zero, true, false, IntPtr.Zero);
        if (evt == IntPtr.Zero) throw new Exception("CreateEventW failed");
        try
        {
            foreach (var item in new KeyValuePair<string, IntPtr>[] {
                new KeyValuePair<string, IntPtr>("current-thread-handle", new IntPtr(-2)),
                new KeyValuePair<string, IntPtr>("event-handle", evt),
                new KeyValuePair<string, IntPtr>("null-handle", IntPtr.Zero)
            })
            {
                for (int i = 0; i < 128; ++i) Marshal.WriteByte(buffer, i, 0xa5);
                Marshal.WriteInt32(returned, unchecked((int)0xa5a5a5a5));
                int status = NtQueryInformationProcess(item.Value, 23, buffer, 36, returned);
                rows.Add(new Dictionary<string, object> {
                    {"label", item.Key}, {"status", unchecked((uint)status)},
                    {"returned", unchecked((uint)Marshal.ReadInt32(returned))},
                    {"after", Hex(buffer, 96)}
                });
            }
            int page = Environment.SystemPageSize;
            foreach (uint length in new uint[] {36, 48})
            foreach (int available in new int[] {4, 32, 36, 40, 44, 48})
            foreach (uint protection in new uint[] {1, 2, 0x102, 0x104})
            {
                IntPtr allocation = VirtualAlloc(IntPtr.Zero, new UIntPtr((uint)(2 * page)), 0x3000, 4);
                if (allocation == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
                try
                {
                    IntPtr second = IntPtr.Add(allocation, page);
                    IntPtr output = IntPtr.Add(second, -available);
                    for (int i = 0; i < 96; ++i) Marshal.WriteByte(output, i, 0xa5);
                    Marshal.WriteInt32(output, IntPtr.Size == 8 ? 40 : 36, 0);
                    string before = Hex(output, 96);
                    uint old;
                    if (!VirtualProtect(second, new UIntPtr((uint)page), protection, out old))
                        throw new Exception("VirtualProtect failed");
                    Marshal.WriteInt32(returned, unchecked((int)0xa5a5a5a5));
                    int status = NtQueryInformationProcess(new IntPtr(-1), 23, output, length, returned);
                    uint remaining;
                    if (!VirtualProtect(second, new UIntPtr((uint)page), 4, out remaining))
                        throw new Exception("VirtualProtect restore failed");
                    rows.Add(new Dictionary<string, object> {
                        {"label", "boundary"}, {"length", length}, {"available", available},
                        {"protection", protection}, {"remaining_protection", remaining},
                        {"status", unchecked((uint)status)},
                        {"returned", unchecked((uint)Marshal.ReadInt32(returned))},
                        {"before", before}, {"after", Hex(output, 96)}
                    });
                }
                finally
                {
                    if (!VirtualFree(allocation, UIntPtr.Zero, 0x8000))
                        throw new Exception("VirtualFree failed");
                }
            }
            if (IntPtr.Size == 4)
            {
                foreach (uint length in new uint[] {36, 48})
                {
                    for (int i = 0; i < 128; ++i) Marshal.WriteByte(buffer, i, 0xa5);
                    Marshal.WriteInt32(buffer, 40, length == 48 ? 1 : 0);
                    Marshal.WriteInt32(returned, unchecked((int)0xa5a5a5a5));
                    try
                    {
                        int status = NtWow64QueryInformationProcess64(new IntPtr(-1), 23, buffer, length, returned);
                        rows.Add(new Dictionary<string, object> {
                            {"label", "wow64-query64"}, {"length", length},
                            {"status", unchecked((uint)status)},
                            {"returned", unchecked((uint)Marshal.ReadInt32(returned))},
                            {"after", Hex(buffer, 96)}
                        });
                    }
                    catch (EntryPointNotFoundException error)
                    {
                        rows.Add(new Dictionary<string, object> {
                            {"label", "wow64-query64"}, {"length", length}, {"error", error.Message}
                        });
                    }
                }
            }
            return rows;
        }
        finally
        {
            CloseHandle(evt);
            Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(returned);
        }
    }
}
