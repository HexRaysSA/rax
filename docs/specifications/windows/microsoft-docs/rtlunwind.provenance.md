# `RtlUnwind` source provenance

- Issuer and title: Microsoft, *RtlUnwind function (winnt.h)*.
- Source: <https://github.com/MicrosoftDocs/sdk-api/blob/a4fd3f7efe2e3378a96c6fe5a6a9455eba9fa021/sdk-api-src/content/winnt/nf-winnt-rtlunwind.md>.
- Retrieval: 2026-09-28 UTC; upstream `docs` commit `a4fd3f7efe2e3378a96c6fe5a6a9455eba9fa021`.
- Upstream SHA-256 (original bytes): `c56cd62ce52b6c67ddbd46288a7fa18c098fcaf90621448ff776ffec0ca50d14`.
- License: MicrosoftDocs SDK API documentation, Creative Commons Attribution 4.0 International; see the adjacent `LICENSE`. The retained markdown normalizes whitespace and nonbreaking spaces.
- Verified contract: a non-null target frame selects the frame, `TargetIp` supplies the continuation, `ReturnValue` supplies the integer return register, and `RtlUnwind` does not return to its caller. The source does not specify x86 ESP restoration or collided-unwind recovery.
- Independent implementation cross-check, not a native Windows oracle: Wine i386 `signal_i386.c` at commit `4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf`, <https://github.com/wine-mirror/wine/blob/4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf/dlls/ntdll/signal_i386.c#L2043-L2140>. It distinguishes `ExceptionContinueSearch`, `ExceptionCollidedUnwind`, and invalid dispositions, but does not prove Windows-native behavior.
