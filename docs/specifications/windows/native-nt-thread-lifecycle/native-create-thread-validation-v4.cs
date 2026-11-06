using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class RaxNativeCreateThreadValidationV4
{
    [DllImport("ntdll.dll")]
    private static extern int NtCreateThreadEx(IntPtr output, uint access, IntPtr attributes,
        IntPtr process, IntPtr entry, IntPtr parameter, uint flags, UIntPtr zeroBits,
        UIntPtr commit, UIntPtr reserve, IntPtr attributeList);
    [DllImport("ntdll.dll")]
    private static extern int NtResumeThread(IntPtr thread, out uint previous);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(IntPtr handle, uint kind, IntPtr output, uint length, out uint returned);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(IntPtr handle, uint kind, IntPtr output, uint length, out uint returned);
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern UIntPtr VirtualQuery(IntPtr address, IntPtr output, UIntPtr length);

    private static void Put(IntPtr buffer, int offset, ulong value)
    {
        Marshal.WriteIntPtr(buffer, offset, new IntPtr(unchecked((long)value)));
    }

    private static ulong Get(IntPtr buffer, int offset)
    {
        return IntPtr.Size == 8 ? unchecked((ulong)Marshal.ReadInt64(buffer, offset)) :
            unchecked((uint)Marshal.ReadInt32(buffer, offset));
    }

    private static bool Changed(IntPtr buffer, int offset, int length)
    {
        for (int index = 0; index < length; ++index)
            if (Marshal.ReadByte(buffer, offset + index) != 0xa5) return true;
        return false;
    }

    private static Dictionary<string, object> Case(string name)
    {
        int p = IntPtr.Size;
        IntPtr memory = Marshal.AllocHGlobal(1024);
        IntPtr thread = IntPtr.Zero;
        var row = new Dictionary<string, object> {{"case", name}};
        try
        {
            for (int index = 0; index < 1024; ++index) Marshal.WriteByte(memory, index, 0xa5);
            IntPtr output = memory;
            IntPtr oa = IntPtr.Zero;
            IntPtr process = new IntPtr(-1);
            IntPtr list = IntPtr.Zero;
            uint access = 0x1fffff, flags = 1;
            ulong zeroBits = 0;
            IntPtr entry = GetProcAddress(GetModuleHandleW("ntdll.dll"), "RtlExitUserThread");
            if (entry == IntPtr.Zero) throw new Exception("RtlExitUserThread not found");

            if (name.StartsWith("oa-"))
            {
                oa = IntPtr.Add(memory, 256 + (name.StartsWith("oa-align-") ? int.Parse(name.Substring(9)) : 0));
                for (int index = 0; index < 6 * p; ++index) Marshal.WriteByte(oa, index, 0);
                Marshal.WriteInt32(oa, 6 * p);
                if (name == "oa-zero-length") Marshal.WriteInt32(oa, 0);
                if (name == "oa-other-width-length") Marshal.WriteInt32(oa, p == 8 ? 24 : 48);
                if (name == "oa-inherit") Marshal.WriteInt32(oa, 3 * p, 2);
                if (name == "oa-exclusive") Marshal.WriteInt32(oa, 3 * p, 0x20);
                if (name == "oa-current-thread-root") Marshal.WriteIntPtr(oa, p, new IntPtr(-2));
                if (name == "oa-bad-pointer") oa = new IntPtr(1);
                if (name == "oa-empty-name")
                {
                    IntPtr unicode = IntPtr.Add(memory, 384);
                    for (int index = 0; index < 2 * p; ++index) Marshal.WriteByte(unicode, index, 0);
                    Marshal.WriteIntPtr(oa, 2 * p, unicode);
                }
            }

            if (name.StartsWith("list-") || name.StartsWith("zero-bits-") || name.StartsWith("cid-align-") || name.StartsWith("return-align-"))
            {
                list = IntPtr.Add(memory, 512 + (name.StartsWith("list-align-") ? int.Parse(name.Substring(11)) : 0));
                Put(list, 0, (ulong)(9 * p));
                Put(list, p, 0x10003); Put(list, 2 * p, (ulong)(2 * p));
                Marshal.WriteIntPtr(list, 3 * p, IntPtr.Add(memory, 32));
                Marshal.WriteIntPtr(list, 4 * p, IntPtr.Add(memory, 64));
                Put(list, 5 * p, 0x10004); Put(list, 6 * p, (ulong)p);
                Marshal.WriteIntPtr(list, 7 * p, IntPtr.Add(memory, 48));
                Marshal.WriteIntPtr(list, 8 * p, IntPtr.Add(memory, 72));
                if (name.StartsWith("cid-align-")) Marshal.WriteIntPtr(list, 3 * p, IntPtr.Add(memory, 128 + int.Parse(name.Substring(10))));
                if (name.StartsWith("return-align-")) Marshal.WriteIntPtr(list, 4 * p, IntPtr.Add(memory, 160 + int.Parse(name.Substring(13))));
                if (name == "list-zero-length") Put(list, 0, 0);
                if (name == "list-header-only") Put(list, 0, (ulong)p);
                if (name == "list-incomplete-entry") Put(list, 0, (ulong)(2 * p));
                if (name == "list-unknown-attribute") Put(list, p, 0x100ff);
                if (name == "list-short-cid") Put(list, 2 * p, (ulong)p);
                if (name == "list-long-teb") Put(list, 6 * p, (ulong)(2 * p));
                if (name == "list-bad-return-length") Marshal.WriteIntPtr(list, 4 * p, new IntPtr(1));
                if (name == "list-bad-output") Marshal.WriteIntPtr(list, 3 * p, new IntPtr(1));
                if (name.StartsWith("zero-bits-")) zeroBits = ulong.Parse(name.Substring(10));
                if (name == "zero-bits-20") zeroBits = 20;
                if (name == "zero-bits-21") zeroBits = 21;
            }

            if (name == "output-null") output = IntPtr.Zero;
            if (name == "output-unaligned") output = IntPtr.Add(memory, 1);
            if (name == "process-null") process = IntPtr.Zero;
            if (name == "process-current-thread") process = new IntPtr(-2);
            if (name == "process-invalid") process = new IntPtr(0x123);
            if (name == "access-zero") access = 0;
            if (name == "flags-reserved-8") flags |= 8;
            if (name == "flags-reserved-80") flags |= 0x80;

            var beforeIds = new HashSet<int>();
            foreach (ProcessThread existing in Process.GetCurrentProcess().Threads) beforeIds.Add(existing.Id);
            int status = NtCreateThreadEx(output, access, oa, process, entry, IntPtr.Zero,
                flags, new UIntPtr(zeroBits), UIntPtr.Zero, UIntPtr.Zero, list);
            row["status"] = unchecked((uint)status);
            row["output_changed"] = Changed(memory, 0, 2 * p);
            row["cid_changed"] = Changed(memory, 32, 2 * p);
            row["teb_changed"] = Changed(memory, 48, p);
            row["cid_returned"] = Get(memory, 64);
            row["teb_returned"] = Get(memory, 72);
            // A WoW64 caller-copy fault can follow successful kernel birth.
            // Retain every published owned handle, even on a failing NTSTATUS.
            if (output != IntPtr.Zero && Changed(memory, 0, 2 * p))
            {
                IntPtr candidate = Marshal.ReadIntPtr(output);
                ulong raw = p == 8 ? unchecked((ulong)candidate.ToInt64()) : unchecked((uint)candidate.ToInt32());
                ulong sentinel = p == 8 ? 0xa5a5a5a5a5a5a5a5UL : 0xa5a5a5a5UL;
                if (raw != 0 && raw != sentinel)
                {
                    row["handle_word_written"] = true;
                    row["handle_word"] = raw;
                    uint returned;
                    int query = NtQueryObject(candidate, 0, IntPtr.Add(memory, 768), 56, out returned);
                    row["handle_query_status"] = unchecked((uint)query);
                    row["handle_published"] = query >= 0;
                    if (query >= 0) thread = candidate;
                }
            }
            if (status < 0)
            {
                int matches = 0;
                foreach (ProcessThread current in Process.GetCurrentProcess().Threads)
                {
                    if (beforeIds.Contains(current.Id)) continue;
                    IntPtr owned = OpenThread(0x100042, false, unchecked((uint)current.Id));
                    if (owned == IntPtr.Zero) continue;
                    uint returned;
                    int query = NtQueryInformationThread(owned, 9, IntPtr.Add(memory, 896), (uint)p, out returned);
                    if (query >= 0 && Marshal.ReadIntPtr(memory, 896) == entry)
                    {
                        ++matches;
                        if (thread == IntPtr.Zero) thread = owned;
                        else CloseHandle(owned);
                    }
                    else CloseHandle(owned);
                }
                row["owned_threads_after_failure"] = matches;
            }
            if (thread != IntPtr.Zero && Changed(memory, 48, p))
            {
                IntPtr teb = Marshal.ReadIntPtr(memory, 48);
                IntPtr stackBase = Marshal.ReadIntPtr(teb, p);
                IntPtr stackLimit = Marshal.ReadIntPtr(teb, 2 * p);
                row["stack_base"] = p == 8 ? unchecked((ulong)stackBase.ToInt64()) : unchecked((uint)stackBase.ToInt32());
                row["committed_bytes"] = unchecked((ulong)(stackBase.ToInt64() - stackLimit.ToInt64()));
                IntPtr information = IntPtr.Add(memory, 768);
                if (VirtualQuery(IntPtr.Add(stackBase, -1), information, new UIntPtr(64)) == UIntPtr.Zero)
                    throw new Exception("VirtualQuery failed");
                IntPtr allocation = Marshal.ReadIntPtr(information, p);
                row["reserved_bytes"] = unchecked((ulong)(stackBase.ToInt64() - allocation.ToInt64()));
            }
            return row;
        }
        finally
        {
            if (thread != IntPtr.Zero)
            {
                uint previous;
                row["resume_status"] = unchecked((uint)NtResumeThread(thread, out previous));
                row["previous_suspend"] = previous;
                row["wait"] = WaitForSingleObject(thread, 0xffffffff);
                row["closed"] = CloseHandle(thread);
            }
            Marshal.FreeHGlobal(memory);
        }
    }

    public static List<Dictionary<string, object>> Run()
    {
        var rows = new List<Dictionary<string, object>>();
        foreach (string name in new string[] {
            "normal", "output-null", "output-unaligned", "process-null",
            "process-current-thread", "process-invalid", "access-zero", "oa-normal",
            "oa-zero-length", "oa-other-width-length", "oa-inherit", "oa-exclusive",
            "oa-current-thread-root", "oa-bad-pointer", "oa-empty-name", "list-normal",
            "list-zero-length", "list-header-only", "list-incomplete-entry",
            "list-unknown-attribute", "list-short-cid", "list-long-teb",
            "list-bad-return-length", "list-bad-output", "zero-bits-1",
            "zero-bits-20", "zero-bits-21", "flags-reserved-8", "flags-reserved-80"
        }) rows.Add(Case(name));
        for (int zeroBits = 2; zeroBits < 20; ++zeroBits) rows.Add(Case("zero-bits-" + zeroBits));
        foreach (int offset in new int[] {1, 2, 3, 4, 5, 7, 8})
            foreach (string kind in new string[] {"oa-align-", "list-align-", "cid-align-", "return-align-"})
                rows.Add(Case(kind + offset));
        return rows;
    }
}
