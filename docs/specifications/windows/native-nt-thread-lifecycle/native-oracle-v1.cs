using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

public static class RaxNativeThreadLifecycleV1
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint StartRoutine(IntPtr parameter);
    private static readonly StartRoutine Entry = RunThread;
    private static int started;

    [DllImport("ntdll.dll")]
    private static extern int NtCreateThreadEx(out IntPtr thread, uint access, IntPtr attributes,
        IntPtr process, IntPtr start, IntPtr parameter, uint flags, UIntPtr zeroBits,
        UIntPtr commit, UIntPtr reserve, IntPtr attributeList);
    [DllImport("ntdll.dll")]
    private static extern int NtResumeThread(IntPtr thread, IntPtr previous);
    [DllImport("ntdll.dll")]
    private static extern int NtSuspendThread(IntPtr thread, IntPtr previous);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(IntPtr handle, uint informationClass, IntPtr buffer,
        uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEventW(IntPtr attributes, bool manual, bool initial, IntPtr name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source,
        IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeThread(IntPtr handle, out uint code);
    [DllImport("kernel32.dll")]
    private static extern uint GetThreadId(IntPtr handle);

    private static uint RunThread(IntPtr control)
    {
        Interlocked.Exchange(ref started, 1);
        return WaitForSingleObject(control, 0xffffffff) == 0 ? 53u : 54u;
    }

    private static void Call(List<Dictionary<string, object>> rows, string label,
        bool suspend, IntPtr handle, IntPtr previous, bool readable)
    {
        if (readable) Marshal.WriteInt32(previous, unchecked((int)0xa5a5a5a5));
        int status = suspend ? NtSuspendThread(handle, previous) : NtResumeThread(handle, previous);
        rows.Add(new Dictionary<string, object> {
            {"label", label}, {"suspend", suspend}, {"status", unchecked((uint)status)},
            {"previous", readable ? (object)unchecked((uint)Marshal.ReadInt32(previous)) : null}
        });
    }

    public static List<Dictionary<string, object>> Run(uint createFlags)
    {
        var rows = new List<Dictionary<string, object>>();
        IntPtr count = Marshal.AllocHGlobal(64);
        for (int i = 0; i < 64; ++i) Marshal.WriteByte(count, i, 0xa5);
        IntPtr control = CreateEventW(IntPtr.Zero, true, false, IntPtr.Zero);
        IntPtr thread = IntPtr.Zero;
        if (control == IntPtr.Zero) throw new Exception("CreateEventW failed");
        try
        {
            started = 0;
            int status = NtCreateThreadEx(out thread, 0x1fffff, IntPtr.Zero, new IntPtr(-1),
                Marshal.GetFunctionPointerForDelegate(Entry), control, createFlags,
                UIntPtr.Zero, UIntPtr.Zero, UIntPtr.Zero, IntPtr.Zero);
            rows.Add(new Dictionary<string, object> {
                {"label", "create"}, {"status", unchecked((uint)status)}, {"flags", createFlags},
                {"thread_created", thread != IntPtr.Zero}, {"started", Volatile.Read(ref started)},
                {"thread_id", thread == IntPtr.Zero ? 0u : GetThreadId(thread)},
                {"pointer_bytes", IntPtr.Size}
            });
            if (status < 0 || thread == IntPtr.Zero) return rows;
            Call(rows, "initial-resume", false, thread, count, true);
            while (Volatile.Read(ref started) == 0) Thread.Sleep(1);
            Call(rows, "suspend-zero", true, thread, count, true);
            Call(rows, "suspend-one", true, thread, count, true);
            Call(rows, "resume-two", false, thread, count, true);
            Call(rows, "resume-one", false, thread, count, true);
            Call(rows, "resume-zero", false, thread, count, true);
            Call(rows, "resume-without-output", false, thread, IntPtr.Zero, false);
            Call(rows, "current-thread-resume", false, new IntPtr(-2), count, true);
            Call(rows, "null-handle-resume", false, IntPtr.Zero, count, true);
            Call(rows, "event-handle-resume", false, control, count, true);
            Call(rows, "null-handle-bad-output", false, IntPtr.Zero, new IntPtr(1), false);
            Call(rows, "thread-bad-output-suspend", true, thread, new IntPtr(1), false);
            Call(rows, "count-after-bad-output", false, thread, count, true);
            foreach (uint access in new uint[] {2, 0x1000, 0x40, 0})
            {
                IntPtr alias;
                if (!DuplicateHandle(new IntPtr(-1), thread, new IntPtr(-1), out alias, access, false, 0))
                {
                    rows.Add(new Dictionary<string, object> {
                        {"label", "duplicate"}, {"requested_access", access},
                        {"error", Marshal.GetLastWin32Error()}
                    });
                    continue;
                }
                try
                {
                    uint returned;
                    for (int i = 0; i < 64; ++i) Marshal.WriteByte(count, i, 0xa5);
                    int query = NtQueryObject(alias, 0, count, 56, out returned);
                    rows.Add(new Dictionary<string, object> {
                        {"label", "alias-grant"}, {"requested_access", access},
                        {"query_status", unchecked((uint)query)},
                        {"granted_access", query >= 0 ? (object)unchecked((uint)Marshal.ReadInt32(count, 4)) : null}
                    });
                    Call(rows, "alias-resume-" + access, false, alias, count, true);
                    Call(rows, "alias-suspend-" + access, true, alias, count, true);
                    Call(rows, "restore-after-alias-" + access, false, thread, count, true);
                }
                finally { CloseHandle(alias); }
            }
            for (int i = 0; i < 128; ++i) Call(rows, "suspend-limit-" + i, true, thread, count, true);
            SetEvent(control);
            for (int i = 0; i < 130; ++i)
            {
                int resume = NtResumeThread(thread, count);
                if (resume < 0 || Marshal.ReadInt32(count) == 0) break;
            }
            uint waited = WaitForSingleObject(thread, 0xffffffff);
            uint exit;
            bool observed = GetExitCodeThread(thread, out exit);
            rows.Add(new Dictionary<string, object> {
                {"label", "thread-terminal"}, {"wait", waited},
                {"exit_observed", observed}, {"exit_code", exit}
            });
            Call(rows, "exited-thread-resume", false, thread, count, true);
            Call(rows, "exited-thread-suspend", true, thread, count, true);
            return rows;
        }
        finally
        {
            if (thread != IntPtr.Zero)
            {
                SetEvent(control);
                for (int i = 0; i < 130; ++i)
                {
                    int status = NtResumeThread(thread, count);
                    if (status < 0 || Marshal.ReadInt32(count) == 0) break;
                }
                WaitForSingleObject(thread, 0xffffffff);
                CloseHandle(thread);
            }
            CloseHandle(control);
            Marshal.FreeHGlobal(count);
            GC.KeepAlive(Entry);
        }
    }
}
