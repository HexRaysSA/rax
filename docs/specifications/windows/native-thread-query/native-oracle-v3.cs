using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class RaxNativeThreadQueryV3
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(IntPtr thread, uint kind,
        IntPtr output, uint length, IntPtr returned);
    [DllImport("ntdll.dll")]
    private static extern int NtCreateThreadEx(out IntPtr thread, uint access,
        IntPtr attributes, IntPtr process, IntPtr start, IntPtr argument,
        uint flags, UIntPtr zeroBits, UIntPtr commit, UIntPtr reserve, IntPtr list);
    [DllImport("ntdll.dll")]
    private static extern int NtResumeThread(IntPtr thread, out uint previous);
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll")]
    private static extern uint GetThreadId(IntPtr handle);
    [DllImport("ntdll.dll")]
    private static extern int NtOpenThread(out IntPtr handle, uint access, IntPtr attributes, IntPtr clientId);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    private static IntPtr OpenCurrent(uint access, out int status)
    {
        int p = IntPtr.Size;
        IntPtr attributes = Marshal.AllocHGlobal(6 * p), client = Marshal.AllocHGlobal(2 * p);
        try
        {
            for (int i = 0; i < 6 * p; ++i) Marshal.WriteByte(attributes, i, 0);
            Marshal.WriteInt32(attributes, 6 * p);
            Marshal.WriteIntPtr(client, new IntPtr(GetCurrentProcessId()));
            Marshal.WriteIntPtr(client, p, new IntPtr(GetCurrentThreadId()));
            IntPtr handle;
            status = NtOpenThread(out handle, access, attributes, client);
            return handle;
        }
        finally { Marshal.FreeHGlobal(client); Marshal.FreeHGlobal(attributes); }
    }

    private static ulong ReadPointer(IntPtr p, int offset)
    {
        return IntPtr.Size == 8 ? unchecked((ulong)Marshal.ReadInt64(p, offset)) :
            unchecked((uint)Marshal.ReadInt32(p, offset));
    }

    private static bool Changed(IntPtr p, int offset, int size)
    {
        for (int i = 0; i < size; ++i)
            if (Marshal.ReadByte(p, offset + i) != 0xa5) return true;
        return false;
    }

    private static Dictionary<string, object> Query(string name, IntPtr handle,
        uint kind, uint length, int outputOffset, int outputMode, int returnMode)
    {
        IntPtr memory = Marshal.AllocHGlobal(512);
        try
        {
            for (int i = 0; i < 512; ++i) Marshal.WriteByte(memory, i, 0xa5);
            IntPtr output = outputMode == 1 ? IntPtr.Zero : outputMode == 2 ?
                new IntPtr(1) : IntPtr.Add(memory, 64 + outputOffset);
            IntPtr returned = returnMode == -1 ? IntPtr.Zero : returnMode == -2 ?
                new IntPtr(1) : IntPtr.Add(memory, 384 + returnMode);
            int status = NtQueryInformationThread(handle, kind, output, length, returned);
            var row = new Dictionary<string, object> {
                {"case", name}, {"class", kind}, {"length", length},
                {"output_offset", outputOffset}, {"output_mode", outputMode},
                {"return_mode", returnMode}, {"status", unchecked((uint)status)},
                {"output_changed", Changed(memory, 64, 160)},
                {"returned_changed", Changed(memory, 384, 12)},
                {"returned_word", unchecked((uint)Marshal.ReadInt32(memory, 384))}
            };
            byte[] bytes = new byte[160];
            Marshal.Copy(IntPtr.Add(memory, 64), bytes, 0, bytes.Length);
            row["output_hex"] = BitConverter.ToString(bytes).Replace("-", "");
            bytes = new byte[12];
            Marshal.Copy(IntPtr.Add(memory, 384), bytes, 0, bytes.Length);
            row["returned_hex"] = BitConverter.ToString(bytes).Replace("-", "");
            if (status >= 0 && outputMode == 0)
            {
                int p = IntPtr.Size;
                if (kind == 0)
                {
                    row["exit_status"] = unchecked((uint)Marshal.ReadInt32(output));
                    row["teb"] = ReadPointer(output, p);
                    row["client_pid"] = ReadPointer(output, 2 * p);
                    row["client_tid"] = ReadPointer(output, 3 * p);
                    row["affinity"] = ReadPointer(output, 4 * p);
                    row["priority"] = Marshal.ReadInt32(output, 5 * p);
                    row["base_priority"] = Marshal.ReadInt32(output, 5 * p + 4);
                }
                else if (kind == 9) row["start_address"] = ReadPointer(output, 0);
                else if (kind == 12) row["last_thread"] = unchecked((uint)Marshal.ReadInt32(output));
            }
            return row;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    public static Dictionary<string, object> Run()
    {
        var rows = new List<Dictionary<string, object>>();
        uint basic = (uint)(IntPtr.Size == 8 ? 48 : 28);
        IntPtr current = new IntPtr(-2);
        foreach (uint kind in new uint[] {0, 9, 12})
        {
            uint expected = kind == 0 ? basic : kind == 9 ? (uint)IntPtr.Size : 4;
            foreach (uint length in new uint[] {0, 1, expected - 1, expected, expected + 1, 128})
                rows.Add(Query("current-length", current, kind, length, 0, 0, 0));
            foreach (int offset in new int[] {0, 1, 2, 3, 4, 7})
            {
                rows.Add(Query("current-output-alignment", current, kind, expected, offset, 0, 0));
                rows.Add(Query("current-return-alignment", current, kind, expected, 0, 0, offset));
            }
            foreach (int outputMode in new int[] {1, 2})
            {
                rows.Add(Query("current-invalid-output", current, kind, expected, 0, outputMode, 0));
                rows.Add(Query("current-invalid-output-zero-length", current, kind, 0, 0, outputMode, 0));
            }
            foreach (int returnMode in new int[] {-1, -2})
            {
                rows.Add(Query("current-return-destination", current, kind, expected, 0, 0, returnMode));
                rows.Add(Query("current-return-zero-length", current, kind, 0, 0, 0, returnMode));
            }
            foreach (IntPtr handle in new IntPtr[] {IntPtr.Zero, new IntPtr(-1)})
            {
                var row = Query("invalid-handle", handle, kind, expected, 0, 0, 0);
                row["handle_role"] = handle == IntPtr.Zero ? "null" : "current-process";
                rows.Add(row);
                row = Query("invalid-handle-zero-length", handle, kind, 0, 0, 0, 0);
                row["handle_role"] = handle == IntPtr.Zero ? "null" : "current-process";
                rows.Add(row);
            }
            foreach (uint rights in new uint[] {0, 2, 0x40, 0x800, 0x1000, 0x2000000})
            {
                int opened;
                IntPtr handle = OpenCurrent(rights, out opened);
                if (opened < 0 || handle == IntPtr.Zero)
                {
                    rows.Add(new Dictionary<string, object>{{"case", "current-handle-open"}, {"class", kind}, {"desired_access", rights}, {"open_status", unchecked((uint)opened)}, {"handle_published", handle != IntPtr.Zero}});
                    if (handle != IntPtr.Zero) CloseHandle(handle);
                    continue;
                }
                try
                {
                    var row = Query("current-handle-rights", handle, kind, expected, 0, 0, 0);
                    row["desired_access"] = rights;
                    rows.Add(row);
                }
                finally { if (!CloseHandle(handle)) throw new Exception("Owned handle close failed"); }
            }
        }
        rows.Add(Query("unknown-class", current, 65535, 0, 0, 0, 0));
        rows.Add(Query("unknown-class-invalid-output", current, 65535, 128, 0, 2, -2));
        IntPtr start = GetProcAddress(GetModuleHandleW("ntdll.dll"), "RtlExitUserThread");
        if (start == IntPtr.Zero) throw new Exception("Owned thread exit routine missing");
        byte[] code = new byte[256];
        Marshal.Copy(start, code, 0, code.Length);
        IntPtr worker = IntPtr.Zero;
        uint waited = 0xffffffff, previous = 0xffffffff;
        int resume = unchecked((int)0xc0000001);
        try
        {
            int created = NtCreateThreadEx(out worker, 0x1fffff, IntPtr.Zero,
                new IntPtr(-1), start, IntPtr.Zero, 1, UIntPtr.Zero,
                UIntPtr.Zero, UIntPtr.Zero, IntPtr.Zero);
            if (created < 0 || worker == IntPtr.Zero) throw new Exception("Owned worker creation failed");
            foreach (uint kind in new uint[] {0, 9, 12})
                rows.Add(Query("owned-suspended", worker, kind,
                    kind == 0 ? basic : kind == 9 ? (uint)IntPtr.Size : 4, 0, 0, 0));
            resume = NtResumeThread(worker, out previous);
            waited = WaitForSingleObject(worker, 0xffffffffu);
            foreach (uint kind in new uint[] {0, 9, 12})
                rows.Add(Query("owned-exited", worker, kind,
                    kind == 0 ? basic : kind == 9 ? (uint)IntPtr.Size : 4, 0, 0, 0));
        }
        finally
        {
            if (worker != IntPtr.Zero)
            {
                if (waited == 0xffffffff)
                {
                    NtResumeThread(worker, out previous);
                    WaitForSingleObject(worker, 0xffffffffu);
                }
                if (!CloseHandle(worker)) throw new Exception("Owned worker close failed");
            }
        }
        return new Dictionary<string, object> {
            {"rows", rows}, {"basic_size", basic}, {"pointer_bytes", IntPtr.Size},
            {"caller_pid", GetCurrentProcessId()}, {"caller_tid", GetCurrentThreadId()},
            {"rtl_exit_user_thread_code", BitConverter.ToString(code).Replace("-", "")},
            {"rtl_exit_user_thread_address", IntPtr.Size == 8 ? unchecked((ulong)start.ToInt64()) : unchecked((uint)start.ToInt32())},
            {"worker_resume_status", unchecked((uint)resume)},
            {"worker_previous_suspend", previous}, {"worker_wait", waited},
            {"owned_worker_closed", true}
        };
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr bytes, uint type, uint protection);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr bytes, uint protection, out uint old);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr address, UIntPtr bytes, uint type);
    [DllImport("kernel32.dll")]
    private static extern UIntPtr VirtualQuery(IntPtr address, IntPtr info, UIntPtr bytes);

    private static uint Protection(IntPtr address)
    {
        IntPtr info = Marshal.AllocHGlobal(64);
        try
        {
            if (VirtualQuery(address, info, new UIntPtr(64)).ToUInt64() == 0)
                throw new Exception("VirtualQuery failed");
            return unchecked((uint)Marshal.ReadInt32(info, IntPtr.Size == 8 ? 36 : 20));
        }
        finally { Marshal.FreeHGlobal(info); }
    }

    private static string Bytes(IntPtr address, int size)
    {
        byte[] bytes = new byte[size];
        Marshal.Copy(address, bytes, 0, size);
        return BitConverter.ToString(bytes).Replace("-", "");
    }

    private static Dictionary<string, object> Boundary(string name, uint kind,
        uint length, int outputOffset, uint outputFirst, uint outputSecond,
        int returnOffset, uint returnFirst, uint returnSecond)
    {
        IntPtr memory = VirtualAlloc(IntPtr.Zero, new UIntPtr(16384), 0x3000, 4);
        if (memory == IntPtr.Zero) throw new Exception("Owned boundary allocation failed");
        uint previous;
        try
        {
            byte[] fill = new byte[16384];
            for (int i = 0; i < fill.Length; ++i) fill[i] = 0xa5;
            Marshal.Copy(fill, 0, memory, fill.Length);
            uint[] protection = new uint[] {outputFirst, outputSecond, returnFirst, returnSecond};
            for (int page = 0; page < 4; ++page)
                if (!VirtualProtect(IntPtr.Add(memory, page * 4096), new UIntPtr(4096), protection[page], out previous))
                    throw new Exception("Owned protection setup failed");
            int status = NtQueryInformationThread(new IntPtr(-2), kind,
                IntPtr.Add(memory, outputOffset), length,
                IntPtr.Add(memory, 8192 + returnOffset));
            uint[] after = new uint[4];
            for (int page = 0; page < 4; ++page)
                after[page] = Protection(IntPtr.Add(memory, page * 4096));
            if (!VirtualProtect(memory, new UIntPtr(16384), 4, out previous))
                throw new Exception("Owned readback setup failed");
            return new Dictionary<string, object> {
                {"case", name}, {"class", kind}, {"length", length},
                {"output_offset", outputOffset}, {"return_offset", returnOffset},
                {"protection_before", protection}, {"protection_after", after},
                {"status", unchecked((uint)status)},
                {"output_prefix_hex", Bytes(memory, 64)},
                {"output_boundary_hex", Bytes(IntPtr.Add(memory, 4032), 128)},
                {"return_prefix_hex", Bytes(IntPtr.Add(memory, 8192), 16)},
                {"return_boundary_hex", Bytes(IntPtr.Add(memory, 12272), 32)}
            };
        }
        finally
        {
            if (!VirtualFree(memory, UIntPtr.Zero, 0x8000))
                throw new Exception("Owned boundary release failed");
        }
    }

    public static Dictionary<string, object> RunBoundary()
    {
        var result = Run();
        var rows = new List<Dictionary<string, object>>();
        foreach (uint kind in new uint[] {0, 9, 12})
        {
            uint expected = kind == 0 ? (uint)(IntPtr.Size == 8 ? 48 : 28) : kind == 9 ? (uint)IntPtr.Size : 4;
            foreach (int remaining in new int[] {4, 8, 16, 24, 48})
                rows.Add(Boundary("output-cross-noaccess", kind, expected, 4096 - remaining, 4, 1, 0, 4, 4));
            foreach (uint protection in new uint[] {1, 2, 0x104, 0x102})
            {
                rows.Add(Boundary("output-protection", kind, expected, 0, protection, 4, 0, 4, 4));
                rows.Add(Boundary("return-protection", kind, expected, 0, 4, 4, 0, protection, 4));
                rows.Add(Boundary("return-protection-zero-length", kind, 0, 0, 4, 4, 0, protection, 4));
            }
            foreach (int remaining in new int[] {1, 2, 3})
                rows.Add(Boundary("return-cross-noaccess", kind, expected, 0, 4, 4, 4096 - remaining, 4, 1));
            rows.Add(Boundary("output-cross-guard", kind, expected, 4080, 4, 0x104, 0, 4, 4));
            rows.Add(Boundary("output-cross-readonly-guard", kind, expected, 4080, 0x104, 0x102, 0, 4, 4));
        }
        foreach (uint kind in new uint[] {59, 60, 61, 64, 65535})
            rows.Add(Query("class-range", new IntPtr(-2), kind, 0, 0, 0, 0));
        result["boundary_rows"] = rows;
        return result;
    }
}
