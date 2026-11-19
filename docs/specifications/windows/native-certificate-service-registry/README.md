# Optional certificate service registry configuration

On Windows 10.0.29708.1003 ARM64, installed `certutil -hashfile` probes
`SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` relative to
the machine hive. The two calls request query-value access and `KEY_READ`,
with `OBJ_CASE_INSENSITIVE` and zero open options. Both return
`STATUS_OBJECT_NAME_NOT_FOUND`.

[Independent native controls](observed-29708.json) replay both access masks,
the default and both explicit registry views, and absolute and machine-relative
spelling. All twelve calls return the same status and clear the handle output.
Installed selection records absence only if a bounded query/enumerate open of
the fixed path reports `ERROR_FILE_NOT_FOUND`. The scope is the absent-key
case. Installed certificate service configuration remains outside the
snapshot if the key is present.
