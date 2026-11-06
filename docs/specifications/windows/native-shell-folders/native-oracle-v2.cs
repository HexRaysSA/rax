using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public static class RaxShellFoldersNativeV2
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyExW(IntPtr root, string path, uint options, uint access, out IntPtr key);
    [DllImport("advapi32.dll")]
    private static extern int RegCloseKey(IntPtr key);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryInfoKeyW(IntPtr key, IntPtr name, IntPtr nameLength,
        IntPtr reserved, out uint children, IntPtr childNameLength, IntPtr childClassLength,
        out uint values, out uint valueNameLength, out uint valueDataLength,
        IntPtr securityLength, out long lastWrite);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegEnumValueW(IntPtr key, uint index, StringBuilder name,
        ref uint nameLength, IntPtr reserved, out uint kind, byte[] data, ref uint dataLength);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryKey(IntPtr key, uint kind, IntPtr output, uint length, out uint returned);
    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(IntPtr key, uint kind, IntPtr output, uint length, out uint returned);

    private static string Canonical(IntPtr key)
    {
        uint length;
        int status = NtQueryKey(key, 3, IntPtr.Zero, 0, out length);
        if (unchecked((uint)status) != 0xc0000023 || length < 4 || length > 65536)
            throw new Exception("NtQueryKey size: " + unchecked((uint)status));
        IntPtr buffer = Marshal.AllocHGlobal((int)length);
        try
        {
            status = NtQueryKey(key, 3, buffer, length, out length);
            if (status != 0) throw new Exception("NtQueryKey: " + unchecked((uint)status));
            uint bytes = unchecked((uint)Marshal.ReadInt32(buffer));
            if ((bytes & 1) != 0 || bytes > length - 4) throw new Exception("Key name bounds");
            return Marshal.PtrToStringUni(IntPtr.Add(buffer, 4), (int)(bytes / 2));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static uint Grant(IntPtr key)
    {
        IntPtr buffer = Marshal.AllocHGlobal(56);
        try
        {
            uint returned;
            int status = NtQueryObject(key, 0, buffer, 56, out returned);
            if (status != 0 || returned != 56)
                throw new Exception("NtQueryObject: " + unchecked((uint)status));
            return unchecked((uint)Marshal.ReadInt32(buffer, 4));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public static Dictionary<string, object> Run()
    {
        string sid = WindowsIdentity.GetCurrent().User.Value;
        string suffix = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
        var rows = new List<Dictionary<string, object>>();
        foreach (uint view in new uint[] {0x100, 0x200})
        {
            IntPtr key;
            int opened = RegOpenKeyExW(new IntPtr(-2147483645L), sid + "\\" + suffix,
                0, 0x02000000 | view, out key);
            var row = new Dictionary<string, object> {{"view", view}, {"open_error", opened}};
            rows.Add(row);
            if (opened != 0) continue;
            try
            {
                string canonical = Canonical(key);
                row["canonical"] = canonical;
                row["maximum_access"] = Grant(key);
                uint children, count, maximumName, maximumData;
                long lastWrite;
                int status = RegQueryInfoKeyW(key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    out children, IntPtr.Zero, IntPtr.Zero, out count,
                    out maximumName, out maximumData, IntPtr.Zero, out lastWrite);
                if (status != 0 || count > 4096 || maximumName > 16383 || maximumData > 1048576)
                    throw new Exception("Key metadata bounds/status: " + status);
                row["children"] = children;
                row["last_write"] = lastWrite;
                var values = new List<Dictionary<string, object>>();
                for (uint index = 0; index < count; ++index)
                {
                    var name = new StringBuilder((int)maximumName + 1);
                    var bytes = new byte[Math.Max(1, (int)maximumData)];
                    uint nameLength = maximumName + 1, dataLength = maximumData, kind;
                    status = RegEnumValueW(key, index, name, ref nameLength, IntPtr.Zero,
                        out kind, bytes, ref dataLength);
                    if (status != 0 || dataLength > bytes.Length || nameLength > maximumName)
                        throw new Exception("Value enumeration bounds/status: " + status);
                    values.Add(new Dictionary<string, object> {
                        {"name", name.ToString()}, {"kind", kind},
                        {"data", BitConverter.ToString(bytes, 0, (int)dataLength).Replace("-", "").ToLowerInvariant()}
                    });
                }
                row["values"] = values;
                uint afterChildren, afterCount, afterName, afterData;
                long afterWrite;
                status = RegQueryInfoKeyW(key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    out afterChildren, IntPtr.Zero, IntPtr.Zero, out afterCount,
                    out afterName, out afterData, IntPtr.Zero, out afterWrite);
                if (status != 0 || children != afterChildren || count != afterCount ||
                    lastWrite != afterWrite || canonical != Canonical(key))
                    throw new Exception("Key changed during observation");
            }
            finally { if (RegCloseKey(key) != 0) throw new Exception("RegCloseKey failed"); }
        }
        return new Dictionary<string, object> {{"creator_sid", sid}, {"pointer_bytes", IntPtr.Size}, {"views", rows}};
    }
}
