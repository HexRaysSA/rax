/* Header-free compiler diagnostic witness; no allocation or execution. */
#ifndef OBJECT_EXTENT
#error OBJECT_EXTENT is required
#endif
extern unsigned char maximum_object[OBJECT_EXTENT];
