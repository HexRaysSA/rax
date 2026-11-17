extern void sink(int fixed, ...);
struct BitFields { _BitInt(7) signed_field:3; unsigned _BitInt(3) unsigned_field:2; int ordinary:3; };
void source_promotions(_BitInt(7) s, unsigned _BitInt(3) u, _BitInt(65) wide, struct BitFields fields) {
    sink(0, s, u, wide, fields.signed_field, fields.unsigned_field, fields.ordinary);
}
