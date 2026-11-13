use super::super::ExecMem;
use super::*;

#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

unsafe extern "system" {
    fn VirtualQuery(
        address: *const c_void,
        information: *mut MemoryBasicInformation,
        size: usize,
    ) -> usize;
}

fn query(address: *const u8) -> MemoryBasicInformation {
    let mut information = MemoryBasicInformation::default();
    let size = core::mem::size_of_val(&information);
    assert_eq!(
        unsafe { VirtualQuery(address.cast(), &mut information, size) },
        size
    );
    information
}

fn return_42() -> Vec<u8> {
    #[cfg(target_arch = "aarch64")]
    let code = [0x52800540u32, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    #[cfg(target_arch = "x86_64")]
    let code = vec![0xb8, 42, 0, 0, 0, 0xc3];
    code
}

#[test]
fn empty_code_never_allocates() {
    assert!(matches!(ExecMem::new(&[]), Err(ExecMemError::Empty)));
}

#[test]
fn executable_mapping_crosses_page_and_allocation_boundaries_and_releases() {
    for entry in [0, 4092, 65532] {
        let mut code = vec![0; entry];
        code.extend(return_42());
        let mapping = ExecMem::new(&code).expect("Windows executable mapping");
        let address = mapping.ptr;
        let information = query(address);
        assert_eq!(information.allocation_base, address.cast());
        assert_eq!(information.state, MEM_COMMIT);
        assert_eq!(information.protect, PAGE_EXECUTE_READ);
        assert!(information.region_size >= code.len());
        assert_eq!(
            query(unsafe { address.add(code.len() - 1) }).protect,
            PAGE_EXECUTE_READ
        );
        let function: unsafe extern "C" fn() -> u32 =
            unsafe { core::mem::transmute(address.add(entry)) };
        assert_eq!(unsafe { function() }, 42);
        drop(mapping);
        assert_eq!(query(address).state, 0x10000, "MEM_FREE after release");
    }
}

#[test]
fn published_code_can_execute_on_another_thread() {
    let mapping = ExecMem::new(&return_42()).expect("Windows executable mapping");
    let mapping = std::sync::Arc::new(mapping);
    let worker_mapping = mapping.clone();
    let result = std::thread::spawn(move || {
        let function: unsafe extern "C" fn() -> u32 =
            unsafe { core::mem::transmute(worker_mapping.ptr) };
        unsafe { function() }
    })
    .join()
    .unwrap();
    assert_eq!(result, 42);
}
