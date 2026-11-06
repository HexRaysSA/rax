using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class RaxNativeCreateThreadV2
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint StartRoutine(IntPtr control);
    private static readonly StartRoutine Entry = Start;
    [DllImport("ntdll.dll")]
    private static extern int NtCreateThreadEx(IntPtr output, uint access, IntPtr attributes,
        IntPtr process, IntPtr entry, IntPtr parameter, uint flags, UIntPtr zeroBits,
        UIntPtr commit, UIntPtr reserve, IntPtr attributeList);
    [DllImport("ntdll.dll")]
    private static extern int NtResumeThread(IntPtr thread, out uint previous);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(IntPtr handle, uint informationClass, IntPtr buffer,
        uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEventW(IntPtr attributes, bool manual, bool initial, IntPtr name);
    [DllImport("kernel32.dll")]
    private static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern UIntPtr VirtualQuery(IntPtr address, IntPtr output, UIntPtr length);
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();

    private static uint Start(IntPtr control)
    {
        return WaitForSingleObject(control, 0xffffffff) == 0 ? 53u : 54u;
    }

    private static void Pointer(IntPtr output, int word, ulong value)
    {
        Marshal.WriteIntPtr(output, word * IntPtr.Size, new IntPtr(unchecked((long)value)));
    }

    private static ulong ReadPointer(IntPtr input, int word)
    {
        return IntPtr.Size == 8 ? unchecked((ulong)Marshal.ReadInt64(input, word * 8)) :
            unchecked((uint)Marshal.ReadInt32(input, word * 4));
    }

    private static IntPtr Address(ulong value)
    {
        return IntPtr.Size == 8 ? new IntPtr(unchecked((long)value)) : new IntPtr(unchecked((int)value));
    }

    private static Dictionary<string, object> Case(uint access, ulong commit, ulong reserve, ulong zeroBits, bool attributes)
    {
        int p = IntPtr.Size;
        IntPtr scratch = Marshal.AllocHGlobal(256);
        IntPtr list = Marshal.AllocHGlobal(9 * p);
        IntPtr gate = CreateEventW(IntPtr.Zero, true, false, IntPtr.Zero);
        IntPtr thread = IntPtr.Zero;
        IntPtr controller = IntPtr.Zero;
        if (gate == IntPtr.Zero) throw new Exception("CreateEventW failed");
        var row = new Dictionary<string, object> {
            {"access", access}, {"commit", commit}, {"reserve", reserve}, {"flags", 1}, {"zero_bits", zeroBits}, {"attributes", attributes}
        };
        try
        {
            for (int i = 0; i < 256; ++i) Marshal.WriteByte(scratch, i, 0xa5);
            Pointer(list, 0, (ulong)(9 * p));
            Pointer(list, 1, 0x10003); Pointer(list, 2, (ulong)(2 * p));
            Pointer(list, 3, unchecked((ulong)IntPtr.Add(scratch, 2 * p).ToInt64()));
            Pointer(list, 4, unchecked((ulong)IntPtr.Add(scratch, 5 * p).ToInt64()));
            Pointer(list, 5, 0x10004); Pointer(list, 6, (ulong)p);
            Pointer(list, 7, unchecked((ulong)IntPtr.Add(scratch, 4 * p).ToInt64()));
            Pointer(list, 8, unchecked((ulong)IntPtr.Add(scratch, 6 * p).ToInt64()));
            int status = NtCreateThreadEx(scratch, access, IntPtr.Zero, new IntPtr(-1),
                Marshal.GetFunctionPointerForDelegate(Entry), gate, 1, new UIntPtr(zeroBits),
                new UIntPtr(commit), new UIntPtr(reserve), attributes ? list : IntPtr.Zero);
            row["status"] = unchecked((uint)status);
            row["cid_process_matches"] = ReadPointer(scratch, 2) == GetCurrentProcessId();
            row["cid_thread_published"] = ReadPointer(scratch, 3) != (p == 8 ? 0xa5a5a5a5a5a5a5a5UL : 0xa5a5a5a5UL);
            row["cid_returned"] = ReadPointer(scratch, 5);
            row["teb_returned"] = ReadPointer(scratch, 6);
            if (status < 0) return row;
            if (!attributes) { thread = Address(ReadPointer(scratch, 0)); row["attribute_outputs_unchanged"] = !((bool)row["cid_thread_published"]); return row; }
            thread = Address(ReadPointer(scratch, 0));
            if (attributes && (!(bool)row["cid_process_matches"] || !(bool)row["cid_thread_published"]))
                throw new Exception("Owned thread client ID was not published");
            uint id = (uint)ReadPointer(scratch, 3);
            controller = OpenThread(0x00100002, false, id);
            if (controller == IntPtr.Zero) throw new Exception("Cannot retain owned thread control");
            IntPtr teb = Address(ReadPointer(scratch, 4));
            IntPtr stackBase = Marshal.ReadIntPtr(teb, p);
            IntPtr stackLimit = Marshal.ReadIntPtr(teb, 2 * p);
            row["committed_bytes"] = unchecked((ulong)(stackBase.ToInt64() - stackLimit.ToInt64()));
            IntPtr information = IntPtr.Add(scratch, 64);
            UIntPtr queried = VirtualQuery(IntPtr.Add(stackBase, -1), information, new UIntPtr(64));
            row["virtual_query_bytes"] = queried.ToUInt64();
            if (queried == UIntPtr.Zero) throw new Exception("VirtualQuery failed");
            IntPtr allocation = Marshal.ReadIntPtr(information, p);
            row["reserved_bytes"] = unchecked((ulong)(stackBase.ToInt64() - allocation.ToInt64()));
            uint returned;
            int query = NtQueryObject(thread, 0, information, 56, out returned);
            row["grant_query_status"] = unchecked((uint)query);
            row["granted_access"] = query < 0 ? (object)null : unchecked((uint)Marshal.ReadInt32(information, 4));
            return row;
        }
        finally
        {
            if (controller == IntPtr.Zero && thread != IntPtr.Zero && access == 0x1fffff)
            {
                controller = thread;
                thread = IntPtr.Zero;
            }
            if (controller != IntPtr.Zero)
            {
                SetEvent(gate);
                uint previous;
                for (int i = 0; i < 130; ++i)
                {
                    int status = NtResumeThread(controller, out previous);
                    if (status < 0 || previous == 0) break;
                }
                row["wait"] = WaitForSingleObject(controller, 0xffffffff);
                CloseHandle(controller);
            }
            if (thread != IntPtr.Zero) CloseHandle(thread);
            CloseHandle(gate);
            Marshal.FreeHGlobal(list);
            Marshal.FreeHGlobal(scratch);
            GC.KeepAlive(Entry);
        }
    }

    public static List<Dictionary<string, object>> Run()
    {
        var rows = new List<Dictionary<string, object>>();
        foreach (ulong[] sizes in new ulong[][] {
            new ulong[] {0, 0}, new ulong[] {0, 65536}, new ulong[] {4096, 65536},
            new ulong[] {65536, 65536}, new ulong[] {4096, 1048576}, new ulong[] {2097152, 1048576}
        }) rows.Add(Case(0x1fffff, sizes[0], sizes[1], 0, true));
        foreach (uint access in new uint[] {0, 2, 0x1000, 0x40, 0x2000000, 0x10000000})
            rows.Add(Case(access, 0, 0, 0, true));
        rows.Add(Case(0x1fffff, 0, 0, 0, false));
        foreach (ulong zeroBits in new ulong[] {1, 21, 32, 33, 64})
            rows.Add(Case(0x1fffff, 4096, 65536, zeroBits, true));
        return rows;
    }
}
