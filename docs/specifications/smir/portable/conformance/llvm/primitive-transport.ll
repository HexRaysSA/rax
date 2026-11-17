; Transport-only witness for instantiated R021 REV2 memory.map.
; Import metadata/admitted context is deliberately absent: this is not executable SMIR.
declare { i32, ptr } @__rax_primitive_memory_map(i64, i64, i32)
define ptr @map_transport(i64 %bytes, i64 %alignment, i32 %permissions, ptr %status_out) {
  %pair = call { i32, ptr } @__rax_primitive_memory_map(i64 %bytes, i64 %alignment, i32 %permissions)
  %status = extractvalue { i32, ptr } %pair, 0
  %pointer = extractvalue { i32, ptr } %pair, 1
  store i32 %status, ptr %status_out
  ret ptr %pointer
}
