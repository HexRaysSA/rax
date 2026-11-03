use super::*;

#[derive(Deserialize)]
struct Row {
    length: u32,
    version: u32,
    offset: u64,
    want_return: u32,
    status: String,
    returned: u32,
    output_size: u32,
    descriptor_tail: String,
    output_prefix: String,
}

#[test]
fn system_policy_replays_native_lengths_alignment_versions_and_optional_return() {
    let texts = [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-system-policy/abi-arm64-v1.jsonl"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-system-policy/abi-x64-v1.jsonl"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-system-policy/abi-x86-v1.jsonl"
            )),
        ),
    ];
    let input = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-policy/abi-input-v1.bin"
    ));
    let mut count = 0;
    for (arch, text) in texts {
        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        native_profile::kernel_profile(p, 29698, 0xAA64);
        p.native.as_mut().unwrap().policy_catalog =
            Ok(Arc::new(crate::user::windows::policy::Catalog::fixture([
                ("Kernel-BrandingInfo", 4, 48u32.to_le_bytes().to_vec()),
            ])));
        let (source, output, returned) = (scratch + 512, scratch + 1024, scratch + 2048);
        let sp = t.cpu.sp();
        for line in text.lines().skip(1) {
            let row: Row = serde_json::from_str(line).unwrap();
            let label = format!(
                "{arch}/{}/{}/{}/{}",
                row.length, row.offset, row.version, row.want_return
            );
            p.space.wr(scratch, &[0xA5; 4096]).unwrap();
            p.space.wr(source, input).unwrap();
            p.space.wr(output, &[0x5A; 512]).unwrap();
            p.space.w32(returned, 0xFEEDFACE).unwrap();
            let descriptor = scratch + row.offset;
            let ptr = arch.ptr_size();
            if ptr == 4 {
                p.space.w32(descriptor, source as u32).unwrap();
                p.space.w32(descriptor + ptr, output as u32).unwrap();
            } else {
                p.space.w64(descriptor, source).unwrap();
                p.space.w64(descriptor + ptr, output).unwrap();
            }
            p.space
                .w32(descriptor + 2 * ptr, input.len() as u32)
                .unwrap();
            p.space.w32(descriptor + 2 * ptr + 4, 512).unwrap();
            p.space.w32(descriptor + 2 * ptr + 8, row.version).unwrap();
            t.cpu.set_sp(sp);
            query_arguments(
                p,
                &mut t,
                134,
                descriptor,
                row.length,
                if row.want_return == 0 { 0 } else { returned },
            );
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(u32::from_str_radix(row.status.trim_start_matches("0x"), 16).unwrap()),
                "{label}"
            );
            assert_eq!(p.space.u32(returned).unwrap(), row.returned, "{label}");
            assert_eq!(
                p.space.u32(descriptor + 2 * ptr + 4).unwrap(),
                row.output_size,
                "{label}"
            );
            assert_eq!(
                p.space.bytes(descriptor + 2 * ptr + 12, 8).unwrap(),
                decode(&row.descriptor_tail),
                "{label}"
            );
            assert_eq!(
                p.space.bytes(output, 8).unwrap(),
                decode(&row.output_prefix),
                "{label}"
            );
            assert_eq!(
                p.space.bytes(source, input.len()).unwrap(),
                input,
                "{label}"
            );
            assert!(t.frames.is_empty(), "{label}");
            count += 1;
        }
    }
    assert_eq!(count, 1350);
}
