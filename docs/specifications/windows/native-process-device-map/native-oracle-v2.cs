using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

public static class RaxNativeProcessDeviceMapV1
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, uint informationClass,
        IntPtr output, uint length, IntPtr returned);
    [DllImport("ntdll.dll")]
    private static extern int NtSuspendThread(IntPtr thread, IntPtr previous);
    [DllImport("ntdll.dll")]
    private static extern int NtResumeThread(IntPtr thread, IntPtr previous);
    [DllImport("kernel32.dll")]
    private static extern uint GetLogicalDrives();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static string Hex(IntPtr pointer, int length)
    {
        var bytes = new byte[length];
        Marshal.Copy(pointer, bytes, 0, length);
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    private static void Query(List<Dictionary<string, object>> rows, string label,
        IntPtr allocation, IntPtr returned, IntPtr handle, int offset, uint length,
        uint flags, bool badOutput, bool badReturned)
    {
        for (int i = 0; i < 256; ++i) Marshal.WriteByte(allocation, i, 0xa5);
        Marshal.WriteInt32(returned, unchecked((int)0xa5a5a5a5));
        int flagsOffset = IntPtr.Size == 8 ? 40 : 36;
        if (!badOutput && offset >= 0)
            Marshal.WriteInt32(allocation, offset + flagsOffset, unchecked((int)flags));
        string before = Hex(allocation, 96);
        IntPtr output = badOutput ? new IntPtr(1) :
            (offset < 0 ? IntPtr.Zero : IntPtr.Add(allocation, offset));
        int status = NtQueryInformationProcess(handle, 23, output, length,
            badReturned ? new IntPtr(1) : returned);
        rows.Add(new Dictionary<string, object> {
            {"label", label}, {"length", length}, {"flags", flags},
            {"output_offset", offset}, {"bad_output", badOutput},
            {"bad_returned", badReturned}, {"handle", handle.ToInt64()},
            {"status", unchecked((uint)status)},
            {"returned", unchecked((uint)Marshal.ReadInt32(returned))},
            {"before", before}, {"after", Hex(allocation, 96)}
        });
    }

    public static List<Dictionary<string, object>> Run()
    {
        var rows = new List<Dictionary<string, object>>();
        uint mask = GetLogicalDrives();
        var types = new List<uint>();
        for (int i = 0; i < 26; ++i) types.Add(GetDriveTypeW(((char)('A' + i)) + ":\\"));
        rows.Add(new Dictionary<string, object> {
            {"label", "logical-drives"}, {"mask", mask}, {"types", types},
            {"pointer_bytes", IntPtr.Size}
        });
        IntPtr allocation = Marshal.AllocHGlobal(256);
        IntPtr returned = Marshal.AllocHGlobal(4);
        try
        {
            foreach (uint length in new uint[] {36, 48})
            {
                Query(rows, "valid-" + length, allocation, returned, new IntPtr(-1), 0, length, 0, false, false);
                Query(rows, "null-handle-" + length, allocation, returned, IntPtr.Zero, 0, length, 0, false, false);
                Query(rows, "null-output-" + length, allocation, returned, new IntPtr(-1), -1, length, 0, false, false);
                Query(rows, "bad-output-" + length, allocation, returned, new IntPtr(-1), 0, length, 0, true, false);
                Query(rows, "null-handle-bad-output-" + length, allocation, returned, IntPtr.Zero, 0, length, 0, true, false);
                Query(rows, "bad-returned-" + length, allocation, returned, new IntPtr(-1), 0, length, 0, false, true);
                Query(rows, "null-handle-bad-returned-" + length, allocation, returned, IntPtr.Zero, 0, length, 0, false, true);
                foreach (int offset in new int[] {1, 2, 3, 4})
                    Query(rows, "offset-" + length + "-" + offset, allocation, returned, new IntPtr(-1), offset, length, 0, false, false);
            }
            foreach (uint flags in new uint[] {1, 2, 0xffffffff})
            {
                Query(rows, "null-handle-flags-" + flags, allocation, returned, IntPtr.Zero, 0, 48, flags, false, false);
                Query(rows, "bad-output-flags-" + flags, allocation, returned, new IntPtr(-1), 0, 48, flags, true, false);
            }
            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(returned);
            Marshal.FreeHGlobal(allocation);
        }
    }

    public static List<Dictionary<string, object>> ThreadAlignment()
    {
        var rows = new List<Dictionary<string, object>>();
        using (var ready = new ManualResetEvent(false))
        using (var control = new ManualResetEvent(false))
        {
            uint id = 0;
            var worker = new Thread(() => {
                id = GetCurrentThreadId();
                ready.Set();
                control.WaitOne();
            });
            worker.Start();
            ready.WaitOne();
            IntPtr handle = OpenThread(2, false, id);
            IntPtr output = Marshal.AllocHGlobal(64);
            try
            {
                if (handle == IntPtr.Zero) throw new Exception("OpenThread failed");
                foreach (int offset in new int[] {0, 1, 2, 3, 4, 7})
                {
                    for (int i = 0; i < 64; ++i) Marshal.WriteByte(output, i, 0xa5);
                    IntPtr previous = IntPtr.Add(output, offset);
                    int suspended = NtSuspendThread(handle, previous);
                    uint before = unchecked((uint)Marshal.ReadInt32(previous));
                    int resumed = NtResumeThread(handle, previous);
                    uint after = unchecked((uint)Marshal.ReadInt32(previous));
                    rows.Add(new Dictionary<string, object> {
                        {"offset", offset}, {"suspend_status", unchecked((uint)suspended)},
                        {"suspend_previous", before}, {"resume_status", unchecked((uint)resumed)},
                        {"resume_previous", after}
                    });
                }
            }
            finally
            {
                if (handle != IntPtr.Zero) NtResumeThread(handle, IntPtr.Zero);
                control.Set();
                worker.Join();
                if (handle != IntPtr.Zero) CloseHandle(handle);
                Marshal.FreeHGlobal(output);
            }
        }
        return rows;
    }
}
