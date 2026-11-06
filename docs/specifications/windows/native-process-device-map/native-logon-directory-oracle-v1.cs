using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class RaxNativeProcessDeviceMapV1
{
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(out IntPtr handle, uint access, ref ObjectAttributes attributes);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(IntPtr handle, IntPtr buffer, uint length,
        byte single, byte restart, ref uint context, out uint returned);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static List<Dictionary<string, object>> Run()
    {
        var rows = new List<Dictionary<string, object>>();
        IntPtr text = Marshal.StringToHGlobalUni("\\??");
        IntPtr name = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
        IntPtr buffer = Marshal.AllocHGlobal(65536);
        IntPtr directory = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(new UnicodeString {Length = 6, MaximumLength = 8, Buffer = text}, name, false);
            var attributes = new ObjectAttributes {
                Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)), ObjectName = name, Attributes = 0x40
            };
            int opened = NtOpenDirectoryObject(out directory, 1, ref attributes);
            rows.Add(new Dictionary<string, object> {{"label", "open-logon-dos-directory"}, {"status", unchecked((uint)opened)}});
            if (opened < 0) return rows;
            uint context = 0;
            uint mask = 0;
            int entries = 0;
            int status = 0;
            for (int i = 0; i < 4096; ++i)
            {
                uint returned;
                status = NtQueryDirectoryObject(directory, buffer, 65536, 1, (byte)(i == 0 ? 1 : 0), ref context, out returned);
                if (unchecked((uint)status) == 0x8000001a) break;
                if (status < 0) break;
                ++entries;
                UnicodeString entry = (UnicodeString)Marshal.PtrToStructure(buffer, typeof(UnicodeString));
                if (entry.Length != 4) continue;
                long offset = entry.Buffer.ToInt64() - buffer.ToInt64();
                if (offset < 0 || offset > 65532) throw new Exception("Name outside owned output buffer");
                char letter = (char)Marshal.ReadInt16(entry.Buffer);
                char colon = (char)Marshal.ReadInt16(entry.Buffer, 2);
                if (letter >= 'A' && letter <= 'Z' && colon == ':') mask |= 1u << (letter - 'A');
            }
            rows.Add(new Dictionary<string, object> {
                {"label", "logon-directory-drive-mask"}, {"mask", mask}, {"entries_examined", entries},
                {"terminal_status", unchecked((uint)status)}, {"pointer_bytes", IntPtr.Size}
            });
            return rows;
        }
        finally
        {
            if (directory != IntPtr.Zero) CloseHandle(directory);
            Marshal.FreeHGlobal(buffer);
            Marshal.FreeHGlobal(name);
            Marshal.FreeHGlobal(text);
        }
    }
}
