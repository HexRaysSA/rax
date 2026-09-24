#![cfg(feature = "x86_64-suite")]

// Aggregated test modules for x86_64 instruction suites.
// Auto-generated - includes all test files

// Common utilities
#[path = "../../../support/x86_64/common/mod.rs"]
mod common;

// Arithmetic
#[path = "integer/arithmetic/aaa_aas.rs"]
mod x86_64_arithmetic_aaa_aas;
#[path = "integer/arithmetic/aam_aad.rs"]
mod x86_64_arithmetic_aam_aad;
#[path = "integer/arithmetic/adc_extended.rs"]
mod x86_64_arithmetic_adc_extended;
#[path = "integer/arithmetic/adcx_adox.rs"]
mod x86_64_arithmetic_adcx_adox;
#[path = "integer/arithmetic/add_extended.rs"]
mod x86_64_arithmetic_add_extended;
#[path = "integer/arithmetic/bcd/aaa.rs"]
mod x86_64_arithmetic_bcd_aaa;
#[path = "integer/arithmetic/bcd/aad.rs"]
mod x86_64_arithmetic_bcd_aad;
#[path = "integer/arithmetic/bcd/aam.rs"]
mod x86_64_arithmetic_bcd_aam;
#[path = "integer/arithmetic/bcd/aas.rs"]
mod x86_64_arithmetic_bcd_aas;
#[path = "integer/arithmetic/bcd/daa.rs"]
mod x86_64_arithmetic_bcd_daa;
#[path = "integer/arithmetic/bcd/das.rs"]
mod x86_64_arithmetic_bcd_das;
#[path = "integer/arithmetic/cmp_extended.rs"]
mod x86_64_arithmetic_cmp_extended;
#[path = "integer/arithmetic/comparison/cmp.rs"]
mod x86_64_arithmetic_comparison_cmp;
#[path = "integer/arithmetic/comprehensive_arithmetic.rs"]
mod x86_64_arithmetic_comprehensive_arithmetic;
#[path = "integer/arithmetic/daa_das.rs"]
mod x86_64_arithmetic_daa_das;
#[path = "integer/arithmetic/div.rs"]
mod x86_64_arithmetic_div;
#[path = "integer/arithmetic/idiv.rs"]
mod x86_64_arithmetic_idiv;
#[path = "integer/arithmetic/inc_dec.rs"]
mod x86_64_arithmetic_inc_dec;
#[path = "integer/arithmetic/integer_addition_carry/adc.rs"]
mod x86_64_arithmetic_integer_addition_carry_adc;
#[path = "integer/arithmetic/integer_addition_carry/add.rs"]
mod x86_64_arithmetic_integer_addition_carry_add;
#[path = "integer/arithmetic/integer_division/div.rs"]
mod x86_64_arithmetic_integer_division_div;
#[path = "integer/arithmetic/integer_division/idiv.rs"]
mod x86_64_arithmetic_integer_division_idiv;
#[path = "integer/arithmetic/integer_multiplication/imul.rs"]
mod x86_64_arithmetic_integer_multiplication_imul;
#[path = "integer/arithmetic/integer_multiplication/mul.rs"]
mod x86_64_arithmetic_integer_multiplication_mul;
#[path = "integer/arithmetic/integer_subtraction_base/sub.rs"]
mod x86_64_arithmetic_integer_subtraction_base_sub;
#[path = "integer/arithmetic/integer_subtraction/dec.rs"]
mod x86_64_arithmetic_integer_subtraction_dec;
#[path = "integer/arithmetic/integer_subtraction/inc.rs"]
mod x86_64_arithmetic_integer_subtraction_inc;
#[path = "integer/arithmetic/integer_subtraction/neg.rs"]
mod x86_64_arithmetic_integer_subtraction_neg;
#[path = "integer/arithmetic/integer_subtraction/sbb.rs"]
mod x86_64_arithmetic_integer_subtraction_sbb;
#[path = "integer/arithmetic/mul.rs"]
mod x86_64_arithmetic_mul;
#[path = "integer/arithmetic/neg.rs"]
mod x86_64_arithmetic_neg;
#[path = "integer/arithmetic/sbb_extended.rs"]
mod x86_64_arithmetic_sbb_extended;
#[path = "integer/arithmetic/sub_extended.rs"]
mod x86_64_arithmetic_sub_extended;

// Bcd
#[path = "integer/arithmetic/bcd/aam_aad_aggregate.rs"]
mod x86_64_bcd_aam_aad;
#[path = "integer/arithmetic/bcd/daa_das_aggregate.rs"]
mod x86_64_bcd_daa_das;

// Bmi
#[path = "integer/bmi/andn.rs"]
mod x86_64_bmi_andn;
#[path = "integer/bmi/bextr.rs"]
mod x86_64_bmi_bextr;
#[path = "integer/bmi/blsi.rs"]
mod x86_64_bmi_blsi;
#[path = "integer/bmi/blsmsk.rs"]
mod x86_64_bmi_blsmsk;
#[path = "integer/bmi/blsr.rs"]
mod x86_64_bmi_blsr;
#[path = "integer/bmi/bmi2_extended.rs"]
mod x86_64_bmi_bmi2_extended;
#[path = "integer/bmi/bzhi_extended.rs"]
mod x86_64_bmi_bzhi_extended;
#[path = "integer/bmi/lzcnt.rs"]
mod x86_64_bmi_lzcnt;
#[path = "integer/bmi/mulx.rs"]
mod x86_64_bmi_mulx;
#[path = "integer/bmi/pdep.rs"]
mod x86_64_bmi_pdep;
#[path = "integer/bmi/pext.rs"]
mod x86_64_bmi_pext;
#[path = "integer/bmi/popcnt.rs"]
mod x86_64_bmi_popcnt;
#[path = "integer/bmi/rorx.rs"]
mod x86_64_bmi_rorx;
#[path = "integer/bmi/rorx_reserved.rs"]
mod x86_64_bmi_rorx_reserved;
#[path = "integer/bmi/sarx_shlx_shrx.rs"]
mod x86_64_bmi_sarx_shlx_shrx;
#[path = "integer/bmi/sarx_shlx_shrx_extended.rs"]
mod x86_64_bmi_sarx_shlx_shrx_extended;
#[path = "integer/bmi/tbm_blcfill.rs"]
mod x86_64_bmi_tbm_blcfill;
#[path = "integer/bmi/tbm_blci.rs"]
mod x86_64_bmi_tbm_blci;
#[path = "integer/bmi/tbm_blcic.rs"]
mod x86_64_bmi_tbm_blcic;
#[path = "integer/bmi/tbm_blcmsk_bextr.rs"]
mod x86_64_bmi_tbm_blcmsk_bextr;
#[path = "integer/bmi/tbm_blcs_blsfill_blsic_t1mskc_tzmsk.rs"]
mod x86_64_bmi_tbm_blcs_blsfill_blsic_t1mskc_tzmsk;
#[path = "integer/bmi/tzcnt.rs"]
mod x86_64_bmi_tzcnt;

// Control Flow
#[path = "control_flow/bound_extended.rs"]
mod x86_64_control_flow_bound_extended;
#[path = "control_flow/call_ret/call.rs"]
mod x86_64_control_flow_call_ret_call;
#[path = "control_flow/call_ret/ret.rs"]
mod x86_64_control_flow_call_ret_ret;
#[path = "control_flow/call_return/call.rs"]
mod x86_64_control_flow_call_return_call;
#[path = "control_flow/call_return/ret.rs"]
mod x86_64_control_flow_call_return_ret;
#[path = "control_flow/conditional_jump/ja.rs"]
mod x86_64_control_flow_conditional_jump_ja;
#[path = "control_flow/conditional_jump/jae.rs"]
mod x86_64_control_flow_conditional_jump_jae;
#[path = "control_flow/conditional_jump/jb.rs"]
mod x86_64_control_flow_conditional_jump_jb;
#[path = "control_flow/conditional_jump/jbe.rs"]
mod x86_64_control_flow_conditional_jump_jbe;
#[path = "control_flow/conditional_jump/je.rs"]
mod x86_64_control_flow_conditional_jump_je;
#[path = "control_flow/conditional_jump/jg.rs"]
mod x86_64_control_flow_conditional_jump_jg;
#[path = "control_flow/conditional_jump/jge.rs"]
mod x86_64_control_flow_conditional_jump_jge;
#[path = "control_flow/conditional_jump/jl.rs"]
mod x86_64_control_flow_conditional_jump_jl;
#[path = "control_flow/conditional_jump/jle.rs"]
mod x86_64_control_flow_conditional_jump_jle;
#[path = "control_flow/conditional_jump/jne.rs"]
mod x86_64_control_flow_conditional_jump_jne;
#[path = "control_flow/conditional_jump/jno.rs"]
mod x86_64_control_flow_conditional_jump_jno;
#[path = "control_flow/conditional_jump/jnp.rs"]
mod x86_64_control_flow_conditional_jump_jnp;
#[path = "control_flow/conditional_jump/jns.rs"]
mod x86_64_control_flow_conditional_jump_jns;
#[path = "control_flow/conditional_jump/jo.rs"]
mod x86_64_control_flow_conditional_jump_jo;
#[path = "control_flow/conditional_jump/jp.rs"]
mod x86_64_control_flow_conditional_jump_jp;
#[path = "control_flow/conditional_jump/js.rs"]
mod x86_64_control_flow_conditional_jump_js;
#[path = "control_flow/far_call.rs"]
mod x86_64_control_flow_far_call;
#[path = "control_flow/far_jmp.rs"]
mod x86_64_control_flow_far_jmp;
#[path = "control_flow/far_ret.rs"]
mod x86_64_control_flow_far_ret;
#[path = "control_flow/int3_prefix.rs"]
mod x86_64_control_flow_int3_prefix;
#[path = "control_flow/int_into_int3.rs"]
mod x86_64_control_flow_int_into_int3;
#[path = "control_flow/iret_iretd_iretq.rs"]
mod x86_64_control_flow_iret_iretd_iretq;
#[path = "control_flow/jcc_all.rs"]
mod x86_64_control_flow_jcc_all;
#[path = "control_flow/jecxz_jrcxz.rs"]
mod x86_64_control_flow_jecxz_jrcxz;
#[path = "control_flow/jump/jmp.rs"]
mod x86_64_control_flow_jump_jmp;
#[path = "control_flow/loop.rs"]
mod x86_64_control_flow_loop;
#[path = "control_flow/loop/loop.rs"]
mod x86_64_control_flow_loop_loop;
#[path = "control_flow/loop/loope.rs"]
mod x86_64_control_flow_loop_loope;
#[path = "control_flow/loop/loopne.rs"]
mod x86_64_control_flow_loop_loopne;
#[path = "control_flow/syscall_sysret.rs"]
mod x86_64_control_flow_syscall_sysret;
#[path = "control_flow/sysenter_sysexit.rs"]
mod x86_64_control_flow_sysenter_sysexit;
#[path = "control_flow/unconditional_jump/jmp.rs"]
mod x86_64_control_flow_unconditional_jump_jmp;

// Conversion
#[path = "data/conversion/cbw_cwde_cdqe.rs"]
mod x86_64_conversion_cbw_cwde_cdqe;
#[path = "data/conversion/cvtpi2pd_cvtpd2pi.rs"]
mod x86_64_conversion_cvtpi2pd_cvtpd2pi;
#[path = "data/conversion/cvtpi2ps_cvtps2pi.rs"]
mod x86_64_conversion_cvtpi2ps_cvtps2pi;
#[path = "data/conversion/cvtss2si_cvtsd2si_extended.rs"]
mod x86_64_conversion_cvtss2si_cvtsd2si_extended;
#[path = "data/conversion/cvttps2pi_cvttpd2pi.rs"]
mod x86_64_conversion_cvttps2pi_cvttpd2pi;
#[path = "data/conversion/cwd_cdq_cqo.rs"]
mod x86_64_conversion_cwd_cdq_cqo;
#[path = "data/conversion/movsx.rs"]
mod x86_64_conversion_movsx;
#[path = "data/conversion/movsxd.rs"]
mod x86_64_conversion_movsxd;
#[path = "data/conversion/movzx.rs"]
mod x86_64_conversion_movzx;

// Crypto
#[path = "crypto/aes_keylocker.rs"]
mod x86_64_crypto_aes_keylocker;
#[path = "crypto/aesdec.rs"]
mod x86_64_crypto_aesdec;
#[path = "crypto/aesdeclast.rs"]
mod x86_64_crypto_aesdeclast;
#[path = "crypto/aesenc.rs"]
mod x86_64_crypto_aesenc;
#[path = "crypto/aesenclast.rs"]
mod x86_64_crypto_aesenclast;
#[path = "crypto/aesimc.rs"]
mod x86_64_crypto_aesimc;
#[path = "crypto/aeskeygenassist.rs"]
mod x86_64_crypto_aeskeygenassist;
#[path = "crypto/galois_field.rs"]
mod x86_64_crypto_galois_field;
#[path = "crypto/gf2p8.rs"]
mod x86_64_crypto_gf2p8;
#[path = "crypto/pclmulqdq.rs"]
mod x86_64_crypto_pclmulqdq;
#[path = "crypto/sha1msg1.rs"]
mod x86_64_crypto_sha1msg1;
#[path = "crypto/sha1msg2.rs"]
mod x86_64_crypto_sha1msg2;
#[path = "crypto/sha1nexte.rs"]
mod x86_64_crypto_sha1nexte;
#[path = "crypto/sha1rnds4.rs"]
mod x86_64_crypto_sha1rnds4;
#[path = "crypto/sha256msg1.rs"]
mod x86_64_crypto_sha256msg1;
#[path = "crypto/sha256msg2.rs"]
mod x86_64_crypto_sha256msg2;
#[path = "crypto/sha256rnds2.rs"]
mod x86_64_crypto_sha256rnds2;
#[path = "crypto/sha_ni_arch.rs"]
mod x86_64_crypto_sha_ni_arch;

// Data Movement
#[path = "data/movement/basic_move/mov.rs"]
mod x86_64_data_movement_basic_move_mov;
#[path = "data/movement/compare_exchange/cmpxchg.rs"]
mod x86_64_data_movement_compare_exchange_cmpxchg;
#[path = "data/movement/conditional_move/cmova.rs"]
mod x86_64_data_movement_conditional_move_cmova;
#[path = "data/movement/conditional_move/cmovae.rs"]
mod x86_64_data_movement_conditional_move_cmovae;
#[path = "data/movement/conditional_move/cmovb.rs"]
mod x86_64_data_movement_conditional_move_cmovb;
#[path = "data/movement/conditional_move/cmovbe.rs"]
mod x86_64_data_movement_conditional_move_cmovbe;
#[path = "data/movement/conditional_move/cmove.rs"]
mod x86_64_data_movement_conditional_move_cmove;
#[path = "data/movement/conditional_move/cmovg.rs"]
mod x86_64_data_movement_conditional_move_cmovg;
#[path = "data/movement/conditional_move/cmovl.rs"]
mod x86_64_data_movement_conditional_move_cmovl;
#[path = "data/movement/conditional_move/cmovne.rs"]
mod x86_64_data_movement_conditional_move_cmovne;
#[path = "data/movement/conditional_move/cmovs.rs"]
mod x86_64_data_movement_conditional_move_cmovs;
#[path = "data/movement/exchange_add/xadd.rs"]
mod x86_64_data_movement_exchange_add_xadd;
#[path = "data/movement/exchange/xchg.rs"]
mod x86_64_data_movement_exchange_xchg;
#[path = "data/movement/extend_move/movsx.rs"]
mod x86_64_data_movement_extend_move_movsx;
#[path = "data/movement/extend_move/movzx.rs"]
mod x86_64_data_movement_extend_move_movzx;
#[path = "data/movement/lea/lea.rs"]
mod x86_64_data_movement_lea_lea;

// Data Transfer
#[path = "data/transfer/bswap.rs"]
mod x86_64_data_transfer_bswap;
#[path = "data/transfer/cdqe_cqo_extended.rs"]
mod x86_64_data_transfer_cdqe_cqo_extended;
#[path = "data/transfer/cmov.rs"]
mod x86_64_data_transfer_cmov;
#[path = "data/transfer/lahf_sahf_extended.rs"]
mod x86_64_data_transfer_lahf_sahf_extended;
#[path = "data/transfer/lea.rs"]
mod x86_64_data_transfer_lea;
#[path = "data/transfer/mov_extended.rs"]
mod x86_64_data_transfer_mov_extended;
#[path = "data/transfer/movbe.rs"]
mod x86_64_data_transfer_movbe;
#[path = "data/transfer/movdir64b.rs"]
mod x86_64_data_transfer_movdir64b;
#[path = "data/transfer/movdiri.rs"]
mod x86_64_data_transfer_movdiri;
#[path = "data/transfer/movsx_extended.rs"]
mod x86_64_data_transfer_movsx_extended;
#[path = "data/transfer/movzx_extended.rs"]
mod x86_64_data_transfer_movzx_extended;
#[path = "data/transfer/pop_extended.rs"]
mod x86_64_data_transfer_pop_extended;
#[path = "data/transfer/push_extended.rs"]
mod x86_64_data_transfer_push_extended;
#[path = "data/transfer/pushad_popad.rs"]
mod x86_64_data_transfer_pushad_popad;
#[path = "data/transfer/setcc.rs"]
mod x86_64_data_transfer_setcc;
#[path = "data/transfer/xchg.rs"]
mod x86_64_data_transfer_xchg;

// Flags
#[path = "integer/flags/clc_stc_cmc.rs"]
mod x86_64_flags_clc_stc_cmc;
#[path = "integer/flags/cld_std.rs"]
mod x86_64_flags_cld_std;
#[path = "integer/flags/lahf_sahf.rs"]
mod x86_64_flags_lahf_sahf;
#[path = "integer/flags/pushf_popf.rs"]
mod x86_64_flags_pushf_popf;

// Fpu
#[path = "floating_point/x87/arithmetic_variants.rs"]
mod x86_64_fpu_arithmetic_variants;
#[path = "floating_point/x87/comparison_control.rs"]
mod x86_64_fpu_comparison_control;
#[path = "floating_point/x87/f2xm1.rs"]
mod x86_64_fpu_f2xm1;
#[path = "floating_point/x87/fabs.rs"]
mod x86_64_fpu_fabs;
#[path = "floating_point/x87/fadd.rs"]
mod x86_64_fpu_fadd;
#[path = "floating_point/x87/faddp_fsubp_fmulp_fdivp.rs"]
mod x86_64_fpu_faddp_fsubp_fmulp_fdivp;
#[path = "floating_point/x87/fbld_fbstp.rs"]
mod x86_64_fpu_fbld_fbstp;
#[path = "floating_point/x87/fchs.rs"]
mod x86_64_fpu_fchs;
#[path = "floating_point/x87/fclex_fnclex.rs"]
mod x86_64_fpu_fclex_fnclex;
#[path = "floating_point/x87/fcmovcc.rs"]
mod x86_64_fpu_fcmovcc;
#[path = "floating_point/x87/fcom.rs"]
mod x86_64_fpu_fcom;
#[path = "floating_point/x87/fcomi_fcomip.rs"]
mod x86_64_fpu_fcomi_fcomip;
#[path = "floating_point/x87/fcompp.rs"]
mod x86_64_fpu_fcompp;
#[path = "floating_point/x87/fcos.rs"]
mod x86_64_fpu_fcos;
#[path = "floating_point/x87/fdiv.rs"]
mod x86_64_fpu_fdiv;
#[path = "floating_point/x87/ffree.rs"]
mod x86_64_fpu_ffree;
#[path = "floating_point/x87/fiadd.rs"]
mod x86_64_fpu_fiadd;
#[path = "floating_point/x87/ficom_ficomp.rs"]
mod x86_64_fpu_ficom_ficomp;
#[path = "floating_point/x87/fidiv.rs"]
mod x86_64_fpu_fidiv;
#[path = "floating_point/x87/fidivr.rs"]
mod x86_64_fpu_fidivr;
#[path = "floating_point/x87/fild.rs"]
mod x86_64_fpu_fild;
#[path = "floating_point/x87/fimul.rs"]
mod x86_64_fpu_fimul;
#[path = "floating_point/x87/fincstp_fdecstp.rs"]
mod x86_64_fpu_fincstp_fdecstp;
#[path = "floating_point/x87/finit_fninit.rs"]
mod x86_64_fpu_finit_fninit;
#[path = "floating_point/x87/fist_fistp.rs"]
mod x86_64_fpu_fist_fistp;
#[path = "floating_point/x87/fisttp.rs"]
mod x86_64_fpu_fisttp;
#[path = "floating_point/x87/fisub.rs"]
mod x86_64_fpu_fisub;
#[path = "floating_point/x87/fisubr.rs"]
mod x86_64_fpu_fisubr;
#[path = "floating_point/x87/fld.rs"]
mod x86_64_fpu_fld;
#[path = "floating_point/x87/fld_constants.rs"]
mod x86_64_fpu_fld_constants;
#[path = "floating_point/x87/fldcw_fstcw.rs"]
mod x86_64_fpu_fldcw_fstcw;
#[path = "floating_point/x87/fldenv_fstenv.rs"]
mod x86_64_fpu_fldenv_fstenv;
#[path = "floating_point/x87/fmul.rs"]
mod x86_64_fpu_fmul;
#[path = "floating_point/x87/fninit_extended.rs"]
mod x86_64_fpu_fninit_extended;
#[path = "floating_point/x87/fnop.rs"]
mod x86_64_fpu_fnop;
#[path = "floating_point/x87/fnsave_fnop.rs"]
mod x86_64_fpu_fnsave_fnop;
#[path = "floating_point/x87/fpatan.rs"]
mod x86_64_fpu_fpatan;
#[path = "floating_point/x87/fprem.rs"]
mod x86_64_fpu_fprem;
#[path = "floating_point/x87/fprem1.rs"]
mod x86_64_fpu_fprem1;
#[path = "floating_point/x87/fptan.rs"]
mod x86_64_fpu_fptan;
#[path = "floating_point/x87/frndint.rs"]
mod x86_64_fpu_frndint;
#[path = "floating_point/x87/frndint_extended.rs"]
mod x86_64_fpu_frndint_extended;
#[path = "floating_point/x87/fsave_frstor.rs"]
mod x86_64_fpu_fsave_frstor;
#[path = "floating_point/x87/fscale.rs"]
mod x86_64_fpu_fscale;
#[path = "floating_point/x87/fsin_fcos.rs"]
mod x86_64_fpu_fsin_fcos;
#[path = "floating_point/x87/fsincos.rs"]
mod x86_64_fpu_fsincos;
#[path = "floating_point/x87/fsqrt.rs"]
mod x86_64_fpu_fsqrt;
#[path = "floating_point/x87/fst_fstp.rs"]
mod x86_64_fpu_fst_fstp;
#[path = "floating_point/x87/fstenv_fnstenv.rs"]
mod x86_64_fpu_fstenv_fnstenv;
#[path = "floating_point/x87/fstsw_fnstsw.rs"]
mod x86_64_fpu_fstsw_fnstsw;
#[path = "floating_point/x87/fsub.rs"]
mod x86_64_fpu_fsub;
#[path = "floating_point/x87/ftst.rs"]
mod x86_64_fpu_ftst;
#[path = "floating_point/x87/fucom_fucomp_fucompp.rs"]
mod x86_64_fpu_fucom_fucomp_fucompp;
#[path = "floating_point/x87/fucomi_fucomip.rs"]
mod x86_64_fpu_fucomi_fucomip;
#[path = "floating_point/x87/fxam.rs"]
mod x86_64_fpu_fxam;
#[path = "floating_point/x87/fxch.rs"]
mod x86_64_fpu_fxch;
#[path = "floating_point/x87/fxsave64_fxrstor64.rs"]
mod x86_64_fpu_fxsave64_fxrstor64;
#[path = "floating_point/x87/fxsave_fxrstor.rs"]
mod x86_64_fpu_fxsave_fxrstor;
#[path = "floating_point/x87/fxtract.rs"]
mod x86_64_fpu_fxtract;
#[path = "floating_point/x87/fyl2x.rs"]
mod x86_64_fpu_fyl2x;
#[path = "floating_point/x87/fyl2xp1.rs"]
mod x86_64_fpu_fyl2xp1;

// Io
#[path = "io/in.rs"]
mod x86_64_io_in;
#[path = "io/in_out.rs"]
mod x86_64_io_in_out;
#[path = "io/ins.rs"]
mod x86_64_io_ins;
#[path = "io/ins_outs.rs"]
mod x86_64_io_ins_outs;
#[path = "io/out.rs"]
mod x86_64_io_out;
#[path = "io/outs.rs"]
mod x86_64_io_outs;
#[path = "io/pit.rs"]
mod x86_64_io_pit;
#[path = "io/serial.rs"]
mod x86_64_io_serial;

// Logic And Bit Manipulation
#[path = "integer/bit_logic/basic_logic/and.rs"]
mod x86_64_logic_and_bit_manipulation_basic_logic_and;
#[path = "integer/bit_logic/basic_logic/not.rs"]
mod x86_64_logic_and_bit_manipulation_basic_logic_not;
#[path = "integer/bit_logic/basic_logic/or.rs"]
mod x86_64_logic_and_bit_manipulation_basic_logic_or;
#[path = "integer/bit_logic/basic_logic/test.rs"]
mod x86_64_logic_and_bit_manipulation_basic_logic_test;
#[path = "integer/bit_logic/basic_logic_xor/xor.rs"]
mod x86_64_logic_and_bit_manipulation_basic_logic_xor_xor;
#[path = "integer/bit_logic/bit_counting_swap/bswap.rs"]
mod x86_64_logic_and_bit_manipulation_bit_counting_swap_bswap;
#[path = "integer/bit_logic/bit_counting_swap/lzcnt.rs"]
mod x86_64_logic_and_bit_manipulation_bit_counting_swap_lzcnt;
#[path = "integer/bit_logic/bit_counting_swap/tzcnt.rs"]
mod x86_64_logic_and_bit_manipulation_bit_counting_swap_tzcnt;
#[path = "integer/bit_logic/bit_scanning/bsf.rs"]
mod x86_64_logic_and_bit_manipulation_bit_scanning_bsf;
#[path = "integer/bit_logic/bit_scanning/bsr.rs"]
mod x86_64_logic_and_bit_manipulation_bit_scanning_bsr;
#[path = "integer/bit_logic/bit_testing/bt.rs"]
mod x86_64_logic_and_bit_manipulation_bit_testing_bt;
#[path = "integer/bit_logic/bit_testing/btc.rs"]
mod x86_64_logic_and_bit_manipulation_bit_testing_btc;
#[path = "integer/bit_logic/bit_testing/btr.rs"]
mod x86_64_logic_and_bit_manipulation_bit_testing_btr;
#[path = "integer/bit_logic/bit_testing/bts.rs"]
mod x86_64_logic_and_bit_manipulation_bit_testing_bts;
#[path = "integer/bit_logic/bmi1/bextr.rs"]
mod x86_64_logic_and_bit_manipulation_bmi1_bextr;
#[path = "integer/bit_logic/bmi1/blsi.rs"]
mod x86_64_logic_and_bit_manipulation_bmi1_blsi;
#[path = "integer/bit_logic/bmi1/blsmsk.rs"]
mod x86_64_logic_and_bit_manipulation_bmi1_blsmsk;
#[path = "integer/bit_logic/bmi1/blsr.rs"]
mod x86_64_logic_and_bit_manipulation_bmi1_blsr;
#[path = "integer/bit_logic/bmi2/bzhi.rs"]
mod x86_64_logic_and_bit_manipulation_bmi2_bzhi;
#[path = "integer/bit_logic/bmi2/pdep.rs"]
mod x86_64_logic_and_bit_manipulation_bmi2_pdep;
#[path = "integer/bit_logic/bmi2/pext.rs"]
mod x86_64_logic_and_bit_manipulation_bmi2_pext;
#[path = "integer/bit_logic/rotates_advanced/rorx.rs"]
mod x86_64_logic_and_bit_manipulation_rotates_advanced_rorx;
#[path = "integer/bit_logic/rotates_basic/rcl.rs"]
mod x86_64_logic_and_bit_manipulation_rotates_basic_rcl;
#[path = "integer/bit_logic/rotates_basic/rcr.rs"]
mod x86_64_logic_and_bit_manipulation_rotates_basic_rcr;
#[path = "integer/bit_logic/rotates_basic/rol.rs"]
mod x86_64_logic_and_bit_manipulation_rotates_basic_rol;
#[path = "integer/bit_logic/rotates_basic/ror.rs"]
mod x86_64_logic_and_bit_manipulation_rotates_basic_ror;
#[path = "integer/bit_logic/shifts_arithmetic/sar.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_arithmetic_sar;
#[path = "integer/bit_logic/shifts_double_precision/shld.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_double_precision_shld;
#[path = "integer/bit_logic/shifts_double_precision/shrd.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_double_precision_shrd;
#[path = "integer/bit_logic/shifts_logical/shl.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_logical_shl;
#[path = "integer/bit_logic/shifts_logical/shr.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_logical_shr;
#[path = "integer/bit_logic/shifts_variable/sarx.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_variable_sarx;
#[path = "integer/bit_logic/shifts_variable/shlx.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_variable_shlx;
#[path = "integer/bit_logic/shifts_variable/shrx.rs"]
mod x86_64_logic_and_bit_manipulation_shifts_variable_shrx;

// Logical
#[path = "integer/logic/and.rs"]
mod x86_64_logical_and;
#[path = "integer/logic/not.rs"]
mod x86_64_logical_not;
#[path = "integer/logic/or.rs"]
mod x86_64_logical_or;
#[path = "integer/logic/sar.rs"]
mod x86_64_logical_sar;
#[path = "integer/logic/shl_sal.rs"]
mod x86_64_logical_shl_sal;
#[path = "integer/logic/shr.rs"]
mod x86_64_logical_shr;
#[path = "integer/logic/test.rs"]
mod x86_64_logical_test;
#[path = "integer/logic/xor.rs"]
mod x86_64_logical_xor;

// Memory
#[path = "memory/bound.rs"]
mod x86_64_memory_bound;
#[path = "memory/enter_leave.rs"]
mod x86_64_memory_enter_leave;
#[path = "memory/mpx.rs"]
mod x86_64_memory_mpx;

// Misc
#[path = "miscellaneous/cldemote.rs"]
mod x86_64_misc_cldemote;
#[path = "miscellaneous/clflush.rs"]
mod x86_64_misc_clflush;
#[path = "miscellaneous/clflush_extended.rs"]
mod x86_64_misc_clflush_extended;
#[path = "miscellaneous/clwb.rs"]
mod x86_64_misc_clwb;
#[path = "miscellaneous/cpuid_extended.rs"]
mod x86_64_misc_cpuid_extended;
#[path = "miscellaneous/crc32.rs"]
mod x86_64_misc_crc32;
#[path = "miscellaneous/endbr32_endbr64.rs"]
mod x86_64_misc_endbr32_endbr64;
#[path = "miscellaneous/hlt.rs"]
mod x86_64_misc_hlt;
#[path = "miscellaneous/lahf_sahf_extended.rs"]
mod x86_64_misc_lahf_sahf_extended;
#[path = "miscellaneous/legacy_instructions.rs"]
mod x86_64_misc_legacy_instructions;
#[path = "miscellaneous/lock.rs"]
mod x86_64_misc_lock;
#[path = "miscellaneous/monitor_mwait.rs"]
mod x86_64_misc_monitor_mwait;
#[path = "miscellaneous/movbe_extended.rs"]
mod x86_64_misc_movbe_extended;
#[path = "miscellaneous/movdir64b_extended.rs"]
mod x86_64_misc_movdir64b_extended;
#[path = "miscellaneous/movdiri_extended.rs"]
mod x86_64_misc_movdiri_extended;
#[path = "miscellaneous/nop.rs"]
mod x86_64_misc_nop;
#[path = "miscellaneous/nop_variants.rs"]
mod x86_64_misc_nop_variants;
#[path = "miscellaneous/pause.rs"]
mod x86_64_misc_pause;
#[path = "miscellaneous/prefetchw_prefetchwt1.rs"]
mod x86_64_misc_prefetchw_prefetchwt1;
#[path = "miscellaneous/rdrand_extended.rs"]
mod x86_64_misc_rdrand_extended;
#[path = "miscellaneous/rdseed_extended.rs"]
mod x86_64_misc_rdseed_extended;
#[path = "miscellaneous/tpause_umonitor_umwait.rs"]
mod x86_64_misc_tpause_umonitor_umwait;
#[path = "miscellaneous/ud.rs"]
mod x86_64_misc_ud;
#[path = "miscellaneous/wait_fwait.rs"]
mod x86_64_misc_wait_fwait;
#[path = "miscellaneous/xgetbv_xsetbv.rs"]
mod x86_64_misc_xgetbv_xsetbv;
#[path = "miscellaneous/xlat.rs"]
mod x86_64_misc_xlat;
#[path = "miscellaneous/xsave_xrstor.rs"]
mod x86_64_misc_xsave_xrstor;

// Rotate
#[path = "integer/shifts/rcl.rs"]
mod x86_64_rotate_rcl;
#[path = "integer/shifts/rcr.rs"]
mod x86_64_rotate_rcr;
#[path = "integer/shifts/rol.rs"]
mod x86_64_rotate_rol;
#[path = "integer/shifts/rol_ror_extended.rs"]
mod x86_64_rotate_rol_ror_extended;
#[path = "integer/shifts/ror.rs"]
mod x86_64_rotate_ror;
#[path = "integer/shifts/shld.rs"]
mod x86_64_rotate_shld;
#[path = "integer/shifts/shld_shrd_extended.rs"]
mod x86_64_rotate_shld_shrd_extended;
#[path = "integer/shifts/shrd.rs"]
mod x86_64_rotate_shrd;

// Segment
#[path = "segments/load_far_pointer.rs"]
mod x86_64_segment_load_far_pointer;
#[path = "segments/mov_segment.rs"]
mod x86_64_segment_mov_segment;
#[path = "segments/push_pop_segment.rs"]
mod x86_64_segment_push_pop_segment;

// Simd
#[path = "simd/avx512/vcompress_vexpand.rs"]
mod simd_avx512_compress_expand;
#[path = "simd/avx2/vbroadcasti128.rs"]
mod x86_64_simd_avx2_vbroadcasti128;
#[path = "simd/avx2/vextracti128.rs"]
mod x86_64_simd_avx2_vextracti128;
#[path = "simd/avx2/vgatherdps_vgatherdpd.rs"]
mod x86_64_simd_avx2_vgatherdps_vgatherdpd;
#[path = "simd/avx2/vgatherqps_vgatherqpd.rs"]
mod x86_64_simd_avx2_vgatherqps_vgatherqpd;
#[path = "simd/avx2/vinserti128.rs"]
mod x86_64_simd_avx2_vinserti128;
#[path = "simd/avx2/vmpsadbw.rs"]
mod x86_64_simd_avx2_vmpsadbw;
#[path = "simd/avx2/vpabsb_vpabsw_vpabsd.rs"]
mod x86_64_simd_avx2_vpabsb_vpabsw_vpabsd;
#[path = "simd/avx2/vpacksswb_vpackssdw.rs"]
mod x86_64_simd_avx2_vpacksswb_vpackssdw;
#[path = "simd/avx2/vpackuswb_vpackusdw.rs"]
mod x86_64_simd_avx2_vpackuswb_vpackusdw;
#[path = "simd/avx2/vpaddb_vpaddw_vpaddd_vpaddq.rs"]
mod x86_64_simd_avx2_vpaddb_vpaddw_vpaddd_vpaddq;
#[path = "simd/avx2/vpaddsb.rs"]
mod x86_64_simd_avx2_vpaddsb;
#[path = "simd/avx2/vpaddsw.rs"]
mod x86_64_simd_avx2_vpaddsw;
#[path = "simd/avx2/vpaddusb.rs"]
mod x86_64_simd_avx2_vpaddusb;
#[path = "simd/avx2/vpaddusw.rs"]
mod x86_64_simd_avx2_vpaddusw;
#[path = "simd/avx2/vpalignr.rs"]
mod x86_64_simd_avx2_vpalignr;
#[path = "simd/avx2/vpand_vpor_vpxor.rs"]
mod x86_64_simd_avx2_vpand_vpor_vpxor;
#[path = "simd/avx2/vpandn.rs"]
mod x86_64_simd_avx2_vpandn;
#[path = "simd/avx2/vpavgb_vpavgw.rs"]
mod x86_64_simd_avx2_vpavgb_vpavgw;
#[path = "simd/avx2/vpblendd.rs"]
mod x86_64_simd_avx2_vpblendd;
#[path = "simd/avx2/vpblendvb.rs"]
mod x86_64_simd_avx2_vpblendvb;
#[path = "simd/avx2/vpblendw.rs"]
mod x86_64_simd_avx2_vpblendw;
#[path = "simd/avx2/vpbroadcastb_vpbroadcastw.rs"]
mod x86_64_simd_avx2_vpbroadcastb_vpbroadcastw;
#[path = "simd/avx2/vpbroadcastd_vpbroadcastq.rs"]
mod x86_64_simd_avx2_vpbroadcastd_vpbroadcastq;
#[path = "simd/avx2/vpcmpeqb_vpcmpeqw_vpcmpeqd_vpcmpeqq.rs"]
mod x86_64_simd_avx2_vpcmpeqb_vpcmpeqw_vpcmpeqd_vpcmpeqq;
#[path = "simd/avx2/vpcmpgtb_vpcmpgtw_vpcmpgtd_vpcmpgtq.rs"]
mod x86_64_simd_avx2_vpcmpgtb_vpcmpgtw_vpcmpgtd_vpcmpgtq;
#[path = "simd/avx2/vperm2i128.rs"]
mod x86_64_simd_avx2_vperm2i128;
#[path = "simd/avx2/vpermd_vpermq.rs"]
mod x86_64_simd_avx2_vpermd_vpermq;
#[path = "simd/avx2/vpermpd.rs"]
mod x86_64_simd_avx2_vpermpd;
#[path = "simd/avx2/vpermps.rs"]
mod x86_64_simd_avx2_vpermps;
#[path = "simd/avx2/vpgatherdd_vpgatherdq.rs"]
mod x86_64_simd_avx2_vpgatherdd_vpgatherdq;
#[path = "simd/avx2/vpgatherqd_vpgatherqq.rs"]
mod x86_64_simd_avx2_vpgatherqd_vpgatherqq;
#[path = "simd/avx2/vphaddsw_vphsubsw.rs"]
mod x86_64_simd_avx2_vphaddsw_vphsubsw;
#[path = "simd/avx2/vphaddw_vphaddd.rs"]
mod x86_64_simd_avx2_vphaddw_vphaddd;
#[path = "simd/avx2/vphminposuw.rs"]
mod x86_64_simd_avx2_vphminposuw;
#[path = "simd/avx2/vphsubw_vphsubd.rs"]
mod x86_64_simd_avx2_vphsubw_vphsubd;
#[path = "simd/avx2/vpmaddubsw.rs"]
mod x86_64_simd_avx2_vpmaddubsw;
#[path = "simd/avx2/vpmaddwd.rs"]
mod x86_64_simd_avx2_vpmaddwd;
#[path = "simd/avx2/vpmaskmovd_vpmaskmovq.rs"]
mod x86_64_simd_avx2_vpmaskmovd_vpmaskmovq;
#[path = "simd/avx2/vpmaxsb_vpmaxsw_vpmaxsd.rs"]
mod x86_64_simd_avx2_vpmaxsb_vpmaxsw_vpmaxsd;
#[path = "simd/avx2/vpmaxub_vpmaxuw_vpmaxud.rs"]
mod x86_64_simd_avx2_vpmaxub_vpmaxuw_vpmaxud;
#[path = "simd/avx2/vpminsb_vpminsw_vpminsd.rs"]
mod x86_64_simd_avx2_vpminsb_vpminsw_vpminsd;
#[path = "simd/avx2/vpminub_vpminuw_vpminud.rs"]
mod x86_64_simd_avx2_vpminub_vpminuw_vpminud;
#[path = "simd/avx2/vpmovmskb.rs"]
mod x86_64_simd_avx2_vpmovmskb;
#[path = "simd/avx2/vpmovsx_variants.rs"]
mod x86_64_simd_avx2_vpmovsx_variants;
#[path = "simd/avx2/vpmovsxbw_vpmovsxbd_vpmovsxbq.rs"]
mod x86_64_simd_avx2_vpmovsxbw_vpmovsxbd_vpmovsxbq;
#[path = "simd/avx2/vpmovzxbw_vpmovzxbd_vpmovzxbq.rs"]
mod x86_64_simd_avx2_vpmovzxbw_vpmovzxbd_vpmovzxbq;
#[path = "simd/avx2/vpmovzxwd_vpmovzxwq_vpmovzxdq.rs"]
mod x86_64_simd_avx2_vpmovzxwd_vpmovzxwq_vpmovzxdq;
#[path = "simd/avx2/vpmuldq.rs"]
mod x86_64_simd_avx2_vpmuldq;
#[path = "simd/avx2/vpmulhrsw.rs"]
mod x86_64_simd_avx2_vpmulhrsw;
#[path = "simd/avx2/vpmulhw_vpmulhuw.rs"]
mod x86_64_simd_avx2_vpmulhw_vpmulhuw;
#[path = "simd/avx2/vpmullw_vpmulld.rs"]
mod x86_64_simd_avx2_vpmullw_vpmulld;
#[path = "simd/avx2/vpmuludq.rs"]
mod x86_64_simd_avx2_vpmuludq;
#[path = "simd/avx2/vpsadbw.rs"]
mod x86_64_simd_avx2_vpsadbw;
#[path = "simd/avx2/vpshufb.rs"]
mod x86_64_simd_avx2_vpshufb;
#[path = "simd/avx2/vpshufd.rs"]
mod x86_64_simd_avx2_vpshufd;
#[path = "simd/avx2/vpshufhw.rs"]
mod x86_64_simd_avx2_vpshufhw;
#[path = "simd/avx2/vpshuflw.rs"]
mod x86_64_simd_avx2_vpshuflw;
#[path = "simd/avx2/vpsignb_vpsignw_vpsignd.rs"]
mod x86_64_simd_avx2_vpsignb_vpsignw_vpsignd;
#[path = "simd/avx2/vpslldq.rs"]
mod x86_64_simd_avx2_vpslldq;
#[path = "simd/avx2/vpsllvd_vpsllvq.rs"]
mod x86_64_simd_avx2_vpsllvd_vpsllvq;
#[path = "simd/avx2/vpsllw_vpslld_vpsllq.rs"]
mod x86_64_simd_avx2_vpsllw_vpslld_vpsllq;
#[path = "simd/avx2/vpsravd.rs"]
mod x86_64_simd_avx2_vpsravd;
#[path = "simd/avx2/vpsraw_vpsrad.rs"]
mod x86_64_simd_avx2_vpsraw_vpsrad;
#[path = "simd/avx2/vpsrldq.rs"]
mod x86_64_simd_avx2_vpsrldq;
#[path = "simd/avx2/vpsrlvd_vpsrlvq.rs"]
mod x86_64_simd_avx2_vpsrlvd_vpsrlvq;
#[path = "simd/avx2/vpsrlw_vpsrld_vpsrlq.rs"]
mod x86_64_simd_avx2_vpsrlw_vpsrld_vpsrlq;
#[path = "simd/avx2/vpsubb_vpsubw_vpsubd_vpsubq.rs"]
mod x86_64_simd_avx2_vpsubb_vpsubw_vpsubd_vpsubq;
#[path = "simd/avx2/vpsubsb.rs"]
mod x86_64_simd_avx2_vpsubsb;
#[path = "simd/avx2/vpsubsw.rs"]
mod x86_64_simd_avx2_vpsubsw;
#[path = "simd/avx2/vpsubusb.rs"]
mod x86_64_simd_avx2_vpsubusb;
#[path = "simd/avx2/vpsubusw.rs"]
mod x86_64_simd_avx2_vpsubusw;
#[path = "simd/avx2/vptest.rs"]
mod x86_64_simd_avx2_vptest;
#[path = "simd/avx2/vpunpckhbw_vpunpckhwd_vpunpckhdq_vpunpckhqdq.rs"]
mod x86_64_simd_avx2_vpunpckhbw_vpunpckhwd_vpunpckhdq_vpunpckhqdq;
#[path = "simd/avx2/vpunpcklbw_vpunpcklwd_vpunpckldq_vpunpcklqdq.rs"]
mod x86_64_simd_avx2_vpunpcklbw_vpunpcklwd_vpunpckldq_vpunpcklqdq;
#[path = "simd/avx512/evex_rex_prefix_ud.rs"]
mod x86_64_simd_avx512_evex_rex_prefix_ud;
#[path = "simd/avx512/evex_rm_reg_ext.rs"]
mod x86_64_simd_avx512_evex_rm_reg_ext;
#[path = "simd/avx512_extended.rs"]
mod x86_64_simd_avx512_extended;
#[path = "simd/avx512/kadd_mask.rs"]
mod x86_64_simd_avx512_kadd_mask;
#[path = "simd/avx512/kand_kor_kxor.rs"]
mod x86_64_simd_avx512_kand_kor_kxor;
#[path = "simd/avx512/kandn_knot_mask.rs"]
mod x86_64_simd_avx512_kandn_knot_mask;
#[path = "simd/avx512/kmov.rs"]
mod x86_64_simd_avx512_kmov;
#[path = "simd/avx512/ktest_kunpck_kshift.rs"]
mod x86_64_simd_avx512_ktest_kunpck_kshift;
#[path = "simd/avx512_mask_ops.rs"]
mod x86_64_simd_avx512_mask_ops;
#[path = "simd/avx512/opmask_oob_ud.rs"]
mod x86_64_simd_avx512_opmask_oob_ud;
#[path = "simd/avx512/vaddph_vsubph_vmulph_vdivph.rs"]
mod x86_64_simd_avx512_vaddph_vsubph_vmulph_vdivph;
#[path = "simd/avx512/vaddps_zmm.rs"]
mod x86_64_simd_avx512_vaddps_zmm;
#[path = "simd/avx512/valign_vprol_vpror_vpternlog.rs"]
mod x86_64_simd_avx512_valign_vprol_vpror_vpternlog;
#[path = "simd/avx512/vcomish_vucomish.rs"]
mod x86_64_simd_avx512_vcomish_vucomish;
#[path = "simd/avx512/vdbpsadbw_vplzcnt_vpshld.rs"]
mod x86_64_simd_avx512_vdbpsadbw_vplzcnt_vpshld;
#[path = "simd/avx512/vdivps_zmm.rs"]
mod x86_64_simd_avx512_vdivps_zmm;
#[path = "simd/avx512/vmovaps_zmm.rs"]
mod x86_64_simd_avx512_vmovaps_zmm;
#[path = "simd/avx512/vmovups_zmm.rs"]
mod x86_64_simd_avx512_vmovups_zmm;
#[path = "simd/avx512/vmulps_zmm.rs"]
mod x86_64_simd_avx512_vmulps_zmm;
#[path = "simd/avx512/vsubps_zmm.rs"]
mod x86_64_simd_avx512_vsubps_zmm;
#[path = "simd/avx/vaddps_vaddpd.rs"]
mod x86_64_simd_avx_vaddps_vaddpd;
#[path = "simd/avx/vaddss_vaddsd.rs"]
mod x86_64_simd_avx_vaddss_vaddsd;
#[path = "simd/avx/vaddsubps_vaddsubpd.rs"]
mod x86_64_simd_avx_vaddsubps_vaddsubpd;
#[path = "simd/avx/vandnps_vandnpd.rs"]
mod x86_64_simd_avx_vandnps_vandnpd;
#[path = "simd/avx/vandps_vandpd.rs"]
mod x86_64_simd_avx_vandps_vandpd;
#[path = "simd/avx/vblendps_vblendpd.rs"]
mod x86_64_simd_avx_vblendps_vblendpd;
#[path = "simd/avx/vblendvpd.rs"]
mod x86_64_simd_avx_vblendvpd;
#[path = "simd/avx/vblendvps.rs"]
mod x86_64_simd_avx_vblendvps;
#[path = "simd/avx/vbroadcastss_vbroadcastsd.rs"]
mod x86_64_simd_avx_vbroadcastss_vbroadcastsd;
#[path = "simd/avx/vcmpps_vcmppd.rs"]
mod x86_64_simd_avx_vcmpps_vcmppd;
#[path = "simd/avx/vcomisd.rs"]
mod x86_64_simd_avx_vcomisd;
#[path = "simd/avx/vcomiss.rs"]
mod x86_64_simd_avx_vcomiss;
#[path = "simd/avx/vcvtdq2pd_vcvtpd2dq.rs"]
mod x86_64_simd_avx_vcvtdq2pd_vcvtpd2dq;
#[path = "simd/avx/vcvtdq2ps_vcvtps2dq.rs"]
mod x86_64_simd_avx_vcvtdq2ps_vcvtps2dq;
#[path = "simd/avx/vcvtps2pd_vcvtpd2ps.rs"]
mod x86_64_simd_avx_vcvtps2pd_vcvtpd2ps;
#[path = "simd/avx/vcvtsi2ss_vcvtsi2sd.rs"]
mod x86_64_simd_avx_vcvtsi2ss_vcvtsi2sd;
#[path = "simd/avx/vcvtss2sd_vcvtsd2ss.rs"]
mod x86_64_simd_avx_vcvtss2sd_vcvtsd2ss;
#[path = "simd/avx/vcvtss2si_vcvtsd2si.rs"]
mod x86_64_simd_avx_vcvtss2si_vcvtsd2si;
#[path = "simd/avx/vcvttps2dq_vcvttpd2dq.rs"]
mod x86_64_simd_avx_vcvttps2dq_vcvttpd2dq;
#[path = "simd/avx/vcvttss2si_vcvttsd2si.rs"]
mod x86_64_simd_avx_vcvttss2si_vcvttsd2si;
#[path = "simd/avx/vdivps_vdivpd.rs"]
mod x86_64_simd_avx_vdivps_vdivpd;
#[path = "simd/avx/vdivss_vdivsd.rs"]
mod x86_64_simd_avx_vdivss_vdivsd;
#[path = "simd/avx/vdppd.rs"]
mod x86_64_simd_avx_vdppd;
#[path = "simd/avx/vdpps.rs"]
mod x86_64_simd_avx_vdpps;
#[path = "simd/avx/vex_legacy_prefix_ud.rs"]
mod x86_64_simd_avx_vex_legacy_prefix_ud;
#[path = "simd/avx/vextractf128.rs"]
mod x86_64_simd_avx_vextractf128;
#[path = "simd/avx/vextractf128_vinsertf128.rs"]
mod x86_64_simd_avx_vextractf128_vinsertf128;
#[path = "simd/avx/vfmadd132pd.rs"]
mod x86_64_simd_avx_vfmadd132pd;
#[path = "simd/avx/vfmadd132ps.rs"]
mod x86_64_simd_avx_vfmadd132ps;
#[path = "simd/avx/vfmadd213pd.rs"]
mod x86_64_simd_avx_vfmadd213pd;
#[path = "simd/avx/vfmadd213ps.rs"]
mod x86_64_simd_avx_vfmadd213ps;
#[path = "simd/avx/vfmadd231pd.rs"]
mod x86_64_simd_avx_vfmadd231pd;
#[path = "simd/avx/vfmadd231ps.rs"]
mod x86_64_simd_avx_vfmadd231ps;
#[path = "simd/avx/vfmsub132pd.rs"]
mod x86_64_simd_avx_vfmsub132pd;
#[path = "simd/avx/vfmsub132ps.rs"]
mod x86_64_simd_avx_vfmsub132ps;
#[path = "simd/avx/vfmsub213pd.rs"]
mod x86_64_simd_avx_vfmsub213pd;
#[path = "simd/avx/vfmsub213ps.rs"]
mod x86_64_simd_avx_vfmsub213ps;
#[path = "simd/avx/vfmsub231pd.rs"]
mod x86_64_simd_avx_vfmsub231pd;
#[path = "simd/avx/vfmsub231ps.rs"]
mod x86_64_simd_avx_vfmsub231ps;
#[path = "simd/avx/vfnmadd132pd.rs"]
mod x86_64_simd_avx_vfnmadd132pd;
#[path = "simd/avx/vfnmadd132ps.rs"]
mod x86_64_simd_avx_vfnmadd132ps;
#[path = "simd/avx/vfnmadd213pd.rs"]
mod x86_64_simd_avx_vfnmadd213pd;
#[path = "simd/avx/vfnmadd213ps.rs"]
mod x86_64_simd_avx_vfnmadd213ps;
#[path = "simd/avx/vfnmadd231pd.rs"]
mod x86_64_simd_avx_vfnmadd231pd;
#[path = "simd/avx/vfnmadd231ps.rs"]
mod x86_64_simd_avx_vfnmadd231ps;
#[path = "simd/avx/vfnmsub132pd.rs"]
mod x86_64_simd_avx_vfnmsub132pd;
#[path = "simd/avx/vfnmsub132ps.rs"]
mod x86_64_simd_avx_vfnmsub132ps;
#[path = "simd/avx/vfnmsub213pd.rs"]
mod x86_64_simd_avx_vfnmsub213pd;
#[path = "simd/avx/vfnmsub213ps.rs"]
mod x86_64_simd_avx_vfnmsub213ps;
#[path = "simd/avx/vfnmsub231pd.rs"]
mod x86_64_simd_avx_vfnmsub231pd;
#[path = "simd/avx/vfnmsub231ps.rs"]
mod x86_64_simd_avx_vfnmsub231ps;
#[path = "simd/avx/vhaddps_vhaddpd.rs"]
mod x86_64_simd_avx_vhaddps_vhaddpd;
#[path = "simd/avx/vhsubps_vhsubpd.rs"]
mod x86_64_simd_avx_vhsubps_vhsubpd;
#[path = "simd/avx/vinsertf128.rs"]
mod x86_64_simd_avx_vinsertf128;
#[path = "simd/avx/vlddqu_vbroadcastf128.rs"]
mod x86_64_simd_avx_vlddqu_vbroadcastf128;
#[path = "simd/avx/vldmxcsr_vstmxcsr.rs"]
mod x86_64_simd_avx_vldmxcsr_vstmxcsr;
#[path = "simd/avx/vmaskmovps_vmaskmovpd.rs"]
mod x86_64_simd_avx_vmaskmovps_vmaskmovpd;
#[path = "simd/avx/vmaxps_vmaxpd.rs"]
mod x86_64_simd_avx_vmaxps_vmaxpd;
#[path = "simd/avx/vminps_vminpd.rs"]
mod x86_64_simd_avx_vminps_vminpd;
#[path = "simd/avx/vmovaps_vmovapd.rs"]
mod x86_64_simd_avx_vmovaps_vmovapd;
#[path = "simd/avx/vmovddup.rs"]
mod x86_64_simd_avx_vmovddup;
#[path = "simd/avx/vmovdqa_vmovdqu.rs"]
mod x86_64_simd_avx_vmovdqa_vmovdqu;
#[path = "simd/avx/vmovhlps.rs"]
mod x86_64_simd_avx_vmovhlps;
#[path = "simd/avx/vmovhpd.rs"]
mod x86_64_simd_avx_vmovhpd;
#[path = "simd/avx/vmovhps.rs"]
mod x86_64_simd_avx_vmovhps;
#[path = "simd/avx/vmovlhps.rs"]
mod x86_64_simd_avx_vmovlhps;
#[path = "simd/avx/vmovlpd.rs"]
mod x86_64_simd_avx_vmovlpd;
#[path = "simd/avx/vmovlps.rs"]
mod x86_64_simd_avx_vmovlps;
#[path = "simd/avx/vmovmskps_vmovmskpd.rs"]
mod x86_64_simd_avx_vmovmskps_vmovmskpd;
#[path = "simd/avx/vmovntdq.rs"]
mod x86_64_simd_avx_vmovntdq;
#[path = "simd/avx/vmovntdqa.rs"]
mod x86_64_simd_avx_vmovntdqa;
#[path = "simd/avx/vmovntpd.rs"]
mod x86_64_simd_avx_vmovntpd;
#[path = "simd/avx/vmovntps.rs"]
mod x86_64_simd_avx_vmovntps;
#[path = "simd/avx/vmovq.rs"]
mod x86_64_simd_avx_vmovq;
#[path = "simd/avx/vmovsd.rs"]
mod x86_64_simd_avx_vmovsd;
#[path = "simd/avx/vmovshdup.rs"]
mod x86_64_simd_avx_vmovshdup;
#[path = "simd/avx/vmovsldup.rs"]
mod x86_64_simd_avx_vmovsldup;
#[path = "simd/avx/vmovss.rs"]
mod x86_64_simd_avx_vmovss;
#[path = "simd/avx/vmovups_vmovupd.rs"]
mod x86_64_simd_avx_vmovups_vmovupd;
#[path = "simd/avx/vmulps_vmulpd.rs"]
mod x86_64_simd_avx_vmulps_vmulpd;
#[path = "simd/avx/vmulss_vmulsd.rs"]
mod x86_64_simd_avx_vmulss_vmulsd;
#[path = "simd/avx/vorps_vorpd.rs"]
mod x86_64_simd_avx_vorps_vorpd;
#[path = "simd/avx/vperm2f128.rs"]
mod x86_64_simd_avx_vperm2f128;
#[path = "simd/avx/vpermilpd.rs"]
mod x86_64_simd_avx_vpermilpd;
#[path = "simd/avx/vpermilps.rs"]
mod x86_64_simd_avx_vpermilps;
#[path = "simd/avx/vptest_vpxor.rs"]
mod x86_64_simd_avx_vptest_vpxor;
#[path = "simd/avx/vrcpps.rs"]
mod x86_64_simd_avx_vrcpps;
#[path = "simd/avx/vroundpd.rs"]
mod x86_64_simd_avx_vroundpd;
#[path = "simd/avx/vroundps.rs"]
mod x86_64_simd_avx_vroundps;
#[path = "simd/avx/vroundsd.rs"]
mod x86_64_simd_avx_vroundsd;
#[path = "simd/avx/vroundss.rs"]
mod x86_64_simd_avx_vroundss;
#[path = "simd/avx/vrsqrtps.rs"]
mod x86_64_simd_avx_vrsqrtps;
#[path = "simd/avx/vshufps_vshufpd.rs"]
mod x86_64_simd_avx_vshufps_vshufpd;
#[path = "simd/avx/vsqrtps_vsqrtpd.rs"]
mod x86_64_simd_avx_vsqrtps_vsqrtpd;
#[path = "simd/avx/vsubps_vsubpd.rs"]
mod x86_64_simd_avx_vsubps_vsubpd;
#[path = "simd/avx/vsubss_vsubsd.rs"]
mod x86_64_simd_avx_vsubss_vsubsd;
#[path = "simd/avx/vtestps_vtestpd.rs"]
mod x86_64_simd_avx_vtestps_vtestpd;
#[path = "simd/avx/vucomisd.rs"]
mod x86_64_simd_avx_vucomisd;
#[path = "simd/avx/vucomiss.rs"]
mod x86_64_simd_avx_vucomiss;
#[path = "simd/avx/vunpckhps_vunpckhpd.rs"]
mod x86_64_simd_avx_vunpckhps_vunpckhpd;
#[path = "simd/avx/vunpcklps_vunpcklpd.rs"]
mod x86_64_simd_avx_vunpcklps_vunpcklpd;
#[path = "simd/avx/vxorps_vxorpd.rs"]
mod x86_64_simd_avx_vxorps_vxorpd;
#[path = "simd/avx/vzeroupper_vzeroall.rs"]
mod x86_64_simd_avx_vzeroupper_vzeroall;
#[path = "simd/fma/vfmadd132pd_vfmadd213pd_vfmadd231pd.rs"]
mod x86_64_simd_fma_vfmadd132pd_vfmadd213pd_vfmadd231pd;
#[path = "simd/fma/vfmadd132ps_vfmadd213ps_vfmadd231ps.rs"]
mod x86_64_simd_fma_vfmadd132ps_vfmadd213ps_vfmadd231ps;
#[path = "simd/fma/vfmadd132sd_vfmadd213sd_vfmadd231sd.rs"]
mod x86_64_simd_fma_vfmadd132sd_vfmadd213sd_vfmadd231sd;
#[path = "simd/fma/vfmadd132ss_vfmadd213ss_vfmadd231ss.rs"]
mod x86_64_simd_fma_vfmadd132ss_vfmadd213ss_vfmadd231ss;
#[path = "simd/fma/vfmaddsub_vfmsubadd.rs"]
mod x86_64_simd_fma_vfmaddsub_vfmsubadd;
#[path = "simd/fma/vfmsub_variants.rs"]
mod x86_64_simd_fma_vfmsub_variants;
#[path = "simd/fma/vfnmadd_variants.rs"]
mod x86_64_simd_fma_vfnmadd_variants;
#[path = "simd/fma/vfnmsub_variants.rs"]
mod x86_64_simd_fma_vfnmsub_variants;
#[path = "simd/mmx/emms.rs"]
mod x86_64_simd_mmx_emms;
#[path = "simd/mmx/movq.rs"]
mod x86_64_simd_mmx_movq;
#[path = "simd/mmx/packsswb_packssdw_mmx.rs"]
mod x86_64_simd_mmx_packsswb_packssdw_mmx;
#[path = "simd/mmx/packuswb_mmx.rs"]
mod x86_64_simd_mmx_packuswb_mmx;
#[path = "simd/mmx/paddb_paddw_paddd.rs"]
mod x86_64_simd_mmx_paddb_paddw_paddd;
#[path = "simd/mmx/paddsb_paddsw_mmx.rs"]
mod x86_64_simd_mmx_paddsb_paddsw_mmx;
#[path = "simd/mmx/paddusb_paddusw_mmx.rs"]
mod x86_64_simd_mmx_paddusb_paddusw_mmx;
#[path = "simd/mmx/pand_por_pxor.rs"]
mod x86_64_simd_mmx_pand_por_pxor;
#[path = "simd/mmx/pandn_mmx.rs"]
mod x86_64_simd_mmx_pandn_mmx;
#[path = "simd/mmx/pcmpeqb_pcmpeqw_pcmpeqd.rs"]
mod x86_64_simd_mmx_pcmpeqb_pcmpeqw_pcmpeqd;
#[path = "simd/mmx/pcmpgtb_pcmpgtw_pcmpgtd_mmx.rs"]
mod x86_64_simd_mmx_pcmpgtb_pcmpgtw_pcmpgtd_mmx;
#[path = "simd/mmx/pmaddwd_mmx.rs"]
mod x86_64_simd_mmx_pmaddwd_mmx;
#[path = "simd/mmx/pmaxsw_mmx.rs"]
mod x86_64_simd_mmx_pmaxsw_mmx;
#[path = "simd/mmx/pmulhw.rs"]
mod x86_64_simd_mmx_pmulhw;
#[path = "simd/mmx/pmullw.rs"]
mod x86_64_simd_mmx_pmullw;
#[path = "simd/mmx/pshufw.rs"]
mod x86_64_simd_mmx_pshufw;
#[path = "simd/mmx/psllw_pslld_psllq_mmx.rs"]
mod x86_64_simd_mmx_psllw_pslld_psllq_mmx;
#[path = "simd/mmx/psraw_psrad_mmx.rs"]
mod x86_64_simd_mmx_psraw_psrad_mmx;
#[path = "simd/mmx/psrlw_psrld_psrlq_mmx.rs"]
mod x86_64_simd_mmx_psrlw_psrld_psrlq_mmx;
#[path = "simd/mmx/psubb_psubw_psubd.rs"]
mod x86_64_simd_mmx_psubb_psubw_psubd;
#[path = "simd/mmx/psubsb_psubsw_mmx.rs"]
mod x86_64_simd_mmx_psubsb_psubsw_mmx;
#[path = "simd/mmx/psubusb_psubusw_mmx.rs"]
mod x86_64_simd_mmx_psubusb_psubusw_mmx;
#[path = "simd/mmx/punpckhbw_punpckhwd.rs"]
mod x86_64_simd_mmx_punpckhbw_punpckhwd;
#[path = "simd/mmx/punpcklbw_punpcklwd.rs"]
mod x86_64_simd_mmx_punpcklbw_punpcklwd;
#[path = "simd/packing_ops.rs"]
mod x86_64_simd_packing_ops;
#[path = "simd/sse/addps_addpd.rs"]
mod x86_64_simd_sse_addps_addpd;
#[path = "simd/sse/addss_addsd.rs"]
mod x86_64_simd_sse_addss_addsd;
#[path = "simd/sse/addsubps_addsubpd.rs"]
mod x86_64_simd_sse_addsubps_addsubpd;
#[path = "simd/sse/aesdec_aesdeclast.rs"]
mod x86_64_simd_sse_aesdec_aesdeclast;
#[path = "simd/sse/aesenc_aesenclast.rs"]
mod x86_64_simd_sse_aesenc_aesenclast;
#[path = "simd/sse/aesimc_aeskeygenassist.rs"]
mod x86_64_simd_sse_aesimc_aeskeygenassist;
#[path = "simd/sse/andnps_andnpd.rs"]
mod x86_64_simd_sse_andnps_andnpd;
#[path = "simd/sse/andps_andpd.rs"]
mod x86_64_simd_sse_andps_andpd;
#[path = "simd/sse/blendps_blendpd.rs"]
mod x86_64_simd_sse_blendps_blendpd;
#[path = "simd/sse/blendvps_blendvpd.rs"]
mod x86_64_simd_sse_blendvps_blendvpd;
#[path = "simd/sse/clflushopt.rs"]
mod x86_64_simd_sse_clflushopt;
#[path = "simd/sse/cmppd.rs"]
mod x86_64_simd_sse_cmppd;
#[path = "simd/sse/cmpps.rs"]
mod x86_64_simd_sse_cmpps;
#[path = "simd/sse/cmpsd.rs"]
mod x86_64_simd_sse_cmpsd;
#[path = "simd/sse/cmpss.rs"]
mod x86_64_simd_sse_cmpss;
#[path = "simd/sse/comiss_comisd.rs"]
mod x86_64_simd_sse_comiss_comisd;
#[path = "simd/sse/crc32.rs"]
mod x86_64_simd_sse_crc32;
#[path = "simd/sse/cvtdq2pd_cvtpd2dq.rs"]
mod x86_64_simd_sse_cvtdq2pd_cvtpd2dq;
#[path = "simd/sse/cvtdq2ps_cvtps2dq.rs"]
mod x86_64_simd_sse_cvtdq2ps_cvtps2dq;
#[path = "simd/sse/cvtpd2ps.rs"]
mod x86_64_simd_sse_cvtpd2ps;
#[path = "simd/sse/cvtpi2pd_cvtpd2pi.rs"]
mod x86_64_simd_sse_cvtpi2pd_cvtpd2pi;
#[path = "simd/sse/cvtpi2ps_cvtps2pi.rs"]
mod x86_64_simd_sse_cvtpi2ps_cvtps2pi;
#[path = "simd/sse/cvtps2pd.rs"]
mod x86_64_simd_sse_cvtps2pd;
#[path = "simd/sse/cvtsd2si.rs"]
mod x86_64_simd_sse_cvtsd2si;
#[path = "simd/sse/cvtsd2ss.rs"]
mod x86_64_simd_sse_cvtsd2ss;
#[path = "simd/sse/cvtsi2sd.rs"]
mod x86_64_simd_sse_cvtsi2sd;
#[path = "simd/sse/cvtsi2ss.rs"]
mod x86_64_simd_sse_cvtsi2ss;
#[path = "simd/sse/cvtss2sd.rs"]
mod x86_64_simd_sse_cvtss2sd;
#[path = "simd/sse/cvtss2si.rs"]
mod x86_64_simd_sse_cvtss2si;
#[path = "simd/sse/cvttps2dq_cvttpd2dq.rs"]
mod x86_64_simd_sse_cvttps2dq_cvttpd2dq;
#[path = "simd/sse/cvttps2pi_cvttpd2pi.rs"]
mod x86_64_simd_sse_cvttps2pi_cvttpd2pi;
#[path = "simd/sse/cvttsd2si_cvttss2si.rs"]
mod x86_64_simd_sse_cvttsd2si_cvttss2si;
#[path = "simd/sse/divps_divpd.rs"]
mod x86_64_simd_sse_divps_divpd;
#[path = "simd/sse/divss_divsd.rs"]
mod x86_64_simd_sse_divss_divsd;
#[path = "simd/sse/dppd.rs"]
mod x86_64_simd_sse_dppd;
#[path = "simd/sse/dpps.rs"]
mod x86_64_simd_sse_dpps;
#[path = "simd/sse/extractps.rs"]
mod x86_64_simd_sse_extractps;
#[path = "simd/sse/fisttp_sse.rs"]
mod x86_64_simd_sse_fisttp_sse;
#[path = "simd/sse/haddps_haddpd.rs"]
mod x86_64_simd_sse_haddps_haddpd;
#[path = "simd/sse/hsubps_hsubpd.rs"]
mod x86_64_simd_sse_hsubps_hsubpd;
#[path = "simd/sse/insertps.rs"]
mod x86_64_simd_sse_insertps;
#[path = "simd/sse/lddqu.rs"]
mod x86_64_simd_sse_lddqu;
#[path = "simd/sse/ldmxcsr_stmxcsr.rs"]
mod x86_64_simd_sse_ldmxcsr_stmxcsr;
#[path = "simd/sse/lfence_mfence_sfence.rs"]
mod x86_64_simd_sse_lfence_mfence_sfence;
#[path = "simd/sse/maskmovdqu.rs"]
mod x86_64_simd_sse_maskmovdqu;
#[path = "simd/sse/maskmovq_emms.rs"]
mod x86_64_simd_sse_maskmovq_emms;
#[path = "simd/sse/maxps_maxpd.rs"]
mod x86_64_simd_sse_maxps_maxpd;
#[path = "simd/sse/maxss_maxsd.rs"]
mod x86_64_simd_sse_maxss_maxsd;
#[path = "simd/sse/minps_minpd.rs"]
mod x86_64_simd_sse_minps_minpd;
#[path = "simd/sse/minss_minsd.rs"]
mod x86_64_simd_sse_minss_minsd;
#[path = "simd/sse/monitor_mwait_extended.rs"]
mod x86_64_simd_sse_monitor_mwait_extended;
#[path = "simd/sse/movapd.rs"]
mod x86_64_simd_sse_movapd;
#[path = "simd/sse/movaps.rs"]
mod x86_64_simd_sse_movaps;
#[path = "simd/sse/movd_movq.rs"]
mod x86_64_simd_sse_movd_movq;
#[path = "simd/sse/movddup.rs"]
mod x86_64_simd_sse_movddup;
#[path = "simd/sse/movddup_extended.rs"]
mod x86_64_simd_sse_movddup_extended;
#[path = "simd/sse/movdqa.rs"]
mod x86_64_simd_sse_movdqa;
#[path = "simd/sse/movdqu.rs"]
mod x86_64_simd_sse_movdqu;
#[path = "simd/sse/movhlps_movlhps.rs"]
mod x86_64_simd_sse_movhlps_movlhps;
#[path = "simd/sse/movhps_movlps_movhpd_movlpd.rs"]
mod x86_64_simd_sse_movhps_movlps_movhpd_movlpd;
#[path = "simd/sse/movmskps_movmskpd.rs"]
mod x86_64_simd_sse_movmskps_movmskpd;
#[path = "simd/sse/movntdq.rs"]
mod x86_64_simd_sse_movntdq;
#[path = "simd/sse/movntdqa.rs"]
mod x86_64_simd_sse_movntdqa;
#[path = "simd/sse/movnti.rs"]
mod x86_64_simd_sse_movnti;
#[path = "simd/sse/movntps_movntpd.rs"]
mod x86_64_simd_sse_movntps_movntpd;
#[path = "simd/sse/movntq.rs"]
mod x86_64_simd_sse_movntq;
#[path = "simd/sse/movntss_movntsd.rs"]
mod x86_64_simd_sse_movntss_movntsd;
#[path = "simd/sse/movq_movq2dq_movdq2q.rs"]
mod x86_64_simd_sse_movq_movq2dq_movdq2q;
#[path = "simd/sse/movshdup_movsldup.rs"]
mod x86_64_simd_sse_movshdup_movsldup;
#[path = "simd/sse/movsldup_movshdup_extended.rs"]
mod x86_64_simd_sse_movsldup_movshdup_extended;
#[path = "simd/sse/movss_movsd_scalar.rs"]
mod x86_64_simd_sse_movss_movsd_scalar;
#[path = "simd/sse/movupd.rs"]
mod x86_64_simd_sse_movupd;
#[path = "simd/sse/movups.rs"]
mod x86_64_simd_sse_movups;
#[path = "simd/sse/mpsadbw.rs"]
mod x86_64_simd_sse_mpsadbw;
#[path = "simd/sse/mpsadbw_extended.rs"]
mod x86_64_simd_sse_mpsadbw_extended;
#[path = "simd/sse/mulps_mulpd.rs"]
mod x86_64_simd_sse_mulps_mulpd;
#[path = "simd/sse/mulss_mulsd.rs"]
mod x86_64_simd_sse_mulss_mulsd;
#[path = "simd/sse/orps_orpd.rs"]
mod x86_64_simd_sse_orps_orpd;
#[path = "simd/sse/pabsb_pabsw_pabsd.rs"]
mod x86_64_simd_sse_pabsb_pabsw_pabsd;
#[path = "simd/sse/packsswb_packssdw.rs"]
mod x86_64_simd_sse_packsswb_packssdw;
#[path = "simd/sse/packusdw.rs"]
mod x86_64_simd_sse_packusdw;
#[path = "simd/sse/packuswb_packusdw.rs"]
mod x86_64_simd_sse_packuswb_packusdw;
#[path = "simd/sse/paddb_paddw_paddd_paddq.rs"]
mod x86_64_simd_sse_paddb_paddw_paddd_paddq;
#[path = "simd/sse/paddsb_paddsw.rs"]
mod x86_64_simd_sse_paddsb_paddsw;
#[path = "simd/sse/paddusb_paddusw.rs"]
mod x86_64_simd_sse_paddusb_paddusw;
#[path = "simd/sse/palignr.rs"]
mod x86_64_simd_sse_palignr;
#[path = "simd/sse/pand_por_pxor_pandn.rs"]
mod x86_64_simd_sse_pand_por_pxor_pandn;
#[path = "simd/sse/pause.rs"]
mod x86_64_simd_sse_pause;
#[path = "simd/sse/pavgb_pavgw.rs"]
mod x86_64_simd_sse_pavgb_pavgw;
#[path = "simd/sse/pblendvb.rs"]
mod x86_64_simd_sse_pblendvb;
#[path = "simd/sse/pblendw.rs"]
mod x86_64_simd_sse_pblendw;
#[path = "simd/sse/pclmulqdq.rs"]
mod x86_64_simd_sse_pclmulqdq;
#[path = "simd/sse/pclmulqdq_extended.rs"]
mod x86_64_simd_sse_pclmulqdq_extended;
#[path = "simd/sse/pcmpeqb_pcmpeqw_pcmpeqd.rs"]
mod x86_64_simd_sse_pcmpeqb_pcmpeqw_pcmpeqd;
#[path = "simd/sse/pcmpeqq.rs"]
mod x86_64_simd_sse_pcmpeqq;
#[path = "simd/sse/pcmpestri.rs"]
mod x86_64_simd_sse_pcmpestri;
#[path = "simd/sse/pcmpestrm.rs"]
mod x86_64_simd_sse_pcmpestrm;
#[path = "simd/sse/pcmpgtb_pcmpgtw_pcmpgtd.rs"]
mod x86_64_simd_sse_pcmpgtb_pcmpgtw_pcmpgtd;
#[path = "simd/sse/pcmpgtq.rs"]
mod x86_64_simd_sse_pcmpgtq;
#[path = "simd/sse/pcmpistri.rs"]
mod x86_64_simd_sse_pcmpistri;
#[path = "simd/sse/pcmpistrm.rs"]
mod x86_64_simd_sse_pcmpistrm;
#[path = "simd/sse/pcmpxstrx_arch.rs"]
mod x86_64_simd_sse_pcmpxstrx_arch;
#[path = "simd/sse/pextrb_pextrd_pextrq.rs"]
mod x86_64_simd_sse_pextrb_pextrd_pextrq;
#[path = "simd/sse/pextrw.rs"]
mod x86_64_simd_sse_pextrw;
#[path = "simd/sse/phaddsw_phsubsw.rs"]
mod x86_64_simd_sse_phaddsw_phsubsw;
#[path = "simd/sse/phaddw_phaddd.rs"]
mod x86_64_simd_sse_phaddw_phaddd;
#[path = "simd/sse/phminposuw.rs"]
mod x86_64_simd_sse_phminposuw;
#[path = "simd/sse/phminposuw_extended.rs"]
mod x86_64_simd_sse_phminposuw_extended;
#[path = "simd/sse/phsubw_phsubd.rs"]
mod x86_64_simd_sse_phsubw_phsubd;
#[path = "simd/sse/pinsrb_pinsrd_pinsrq.rs"]
mod x86_64_simd_sse_pinsrb_pinsrd_pinsrq;
#[path = "simd/sse/pinsrw.rs"]
mod x86_64_simd_sse_pinsrw;
#[path = "simd/sse/pmaddubsw.rs"]
mod x86_64_simd_sse_pmaddubsw;
#[path = "simd/sse/pmaddubsw_extended.rs"]
mod x86_64_simd_sse_pmaddubsw_extended;
#[path = "simd/sse/pmaddwd.rs"]
mod x86_64_simd_sse_pmaddwd;
#[path = "simd/sse/pmaxsb_pmaxsd.rs"]
mod x86_64_simd_sse_pmaxsb_pmaxsd;
#[path = "simd/sse/pmaxsb_pmaxsw_pmaxsd.rs"]
mod x86_64_simd_sse_pmaxsb_pmaxsw_pmaxsd;
#[path = "simd/sse/pmaxub_pmaxuw_extended.rs"]
mod x86_64_simd_sse_pmaxub_pmaxuw_extended;
#[path = "simd/sse/pmaxub_pmaxuw_pmaxud.rs"]
mod x86_64_simd_sse_pmaxub_pmaxuw_pmaxud;
#[path = "simd/sse/pmaxuw_pmaxud.rs"]
mod x86_64_simd_sse_pmaxuw_pmaxud;
#[path = "simd/sse/pminsb_pminsd.rs"]
mod x86_64_simd_sse_pminsb_pminsd;
#[path = "simd/sse/pminsb_pminsw_pminsd.rs"]
mod x86_64_simd_sse_pminsb_pminsw_pminsd;
#[path = "simd/sse/pminub_pminuw_extended.rs"]
mod x86_64_simd_sse_pminub_pminuw_extended;
#[path = "simd/sse/pminub_pminuw_pminud.rs"]
mod x86_64_simd_sse_pminub_pminuw_pminud;
#[path = "simd/sse/pminuw_pminud.rs"]
mod x86_64_simd_sse_pminuw_pminud;
#[path = "simd/sse/pmovmskb.rs"]
mod x86_64_simd_sse_pmovmskb;
#[path = "simd/sse/pmovsxbw_pmovsxbd_pmovsxbq.rs"]
mod x86_64_simd_sse_pmovsxbw_pmovsxbd_pmovsxbq;
#[path = "simd/sse/pmovsxwd_pmovsxwq_pmovsxdq.rs"]
mod x86_64_simd_sse_pmovsxwd_pmovsxwq_pmovsxdq;
#[path = "simd/sse/pmovzxbw_pmovzxbd_pmovzxbq.rs"]
mod x86_64_simd_sse_pmovzxbw_pmovzxbd_pmovzxbq;
#[path = "simd/sse/pmovzxwd_pmovzxwq_pmovzxdq.rs"]
mod x86_64_simd_sse_pmovzxwd_pmovzxwq_pmovzxdq;
#[path = "simd/sse/pmuldq.rs"]
mod x86_64_simd_sse_pmuldq;
#[path = "simd/sse/pmulhrsw.rs"]
mod x86_64_simd_sse_pmulhrsw;
#[path = "simd/sse/pmulhuw.rs"]
mod x86_64_simd_sse_pmulhuw;
#[path = "simd/sse/pmulhw.rs"]
mod x86_64_simd_sse_pmulhw;
#[path = "simd/sse/pmulld.rs"]
mod x86_64_simd_sse_pmulld;
#[path = "simd/sse/pmullq.rs"]
mod x86_64_simd_sse_pmullq;
#[path = "simd/sse/pmullw.rs"]
mod x86_64_simd_sse_pmullw;
#[path = "simd/sse/pmuludq.rs"]
mod x86_64_simd_sse_pmuludq;
#[path = "simd/sse/prefetchnta_prefetcht0_prefetcht1_prefetcht2.rs"]
mod x86_64_simd_sse_prefetchnta_prefetcht0_prefetcht1_prefetcht2;
#[path = "simd/sse/psadbw.rs"]
mod x86_64_simd_sse_psadbw;
#[path = "simd/sse/pshufb.rs"]
mod x86_64_simd_sse_pshufb;
#[path = "simd/sse/pshufd.rs"]
mod x86_64_simd_sse_pshufd;
#[path = "simd/sse/pshufhw.rs"]
mod x86_64_simd_sse_pshufhw;
#[path = "simd/sse/pshuflw.rs"]
mod x86_64_simd_sse_pshuflw;
#[path = "simd/sse/pshufw.rs"]
mod x86_64_simd_sse_pshufw;
#[path = "simd/sse/psignb_psignw_psignd.rs"]
mod x86_64_simd_sse_psignb_psignw_psignd;
#[path = "simd/sse/pslldq_psrldq.rs"]
mod x86_64_simd_sse_pslldq_psrldq;
#[path = "simd/sse/psllw_pslld_psllq.rs"]
mod x86_64_simd_sse_psllw_pslld_psllq;
#[path = "simd/sse/psraw_psrad.rs"]
mod x86_64_simd_sse_psraw_psrad;
#[path = "simd/sse/psrlw_psrld_psrlq.rs"]
mod x86_64_simd_sse_psrlw_psrld_psrlq;
#[path = "simd/sse/psubb_psubw_psubd_psubq.rs"]
mod x86_64_simd_sse_psubb_psubw_psubd_psubq;
#[path = "simd/sse/psubsb_psubsw.rs"]
mod x86_64_simd_sse_psubsb_psubsw;
#[path = "simd/sse/psubusb_psubusw.rs"]
mod x86_64_simd_sse_psubusb_psubusw;
#[path = "simd/sse/ptest.rs"]
mod x86_64_simd_sse_ptest;
#[path = "simd/sse/punpckhbw_punpckhwd_punpckhdq_punpckhqdq.rs"]
mod x86_64_simd_sse_punpckhbw_punpckhwd_punpckhdq_punpckhqdq;
#[path = "simd/sse/punpcklbw_punpcklwd_punpckldq_punpcklqdq.rs"]
mod x86_64_simd_sse_punpcklbw_punpcklwd_punpckldq_punpcklqdq;
#[path = "simd/sse/rcpps.rs"]
mod x86_64_simd_sse_rcpps;
#[path = "simd/sse/rcpss.rs"]
mod x86_64_simd_sse_rcpss;
#[path = "simd/sse/roundps_roundpd.rs"]
mod x86_64_simd_sse_roundps_roundpd;
#[path = "simd/sse/roundss_roundsd.rs"]
mod x86_64_simd_sse_roundss_roundsd;
#[path = "simd/sse/rsqrtps.rs"]
mod x86_64_simd_sse_rsqrtps;
#[path = "simd/sse/rsqrtss.rs"]
mod x86_64_simd_sse_rsqrtss;
#[path = "simd/sse/shufpd.rs"]
mod x86_64_simd_sse_shufpd;
#[path = "simd/sse/shufps.rs"]
mod x86_64_simd_sse_shufps;
#[path = "simd/sse/sqrtps_sqrtpd.rs"]
mod x86_64_simd_sse_sqrtps_sqrtpd;
#[path = "simd/sse/sqrtss_sqrtsd.rs"]
mod x86_64_simd_sse_sqrtss_sqrtsd;
#[path = "simd/sse/subps_subpd.rs"]
mod x86_64_simd_sse_subps_subpd;
#[path = "simd/sse/subss_subsd.rs"]
mod x86_64_simd_sse_subss_subsd;
#[path = "simd/sse/ucomiss_ucomisd.rs"]
mod x86_64_simd_sse_ucomiss_ucomisd;
#[path = "simd/sse/unpckhpd.rs"]
mod x86_64_simd_sse_unpckhpd;
#[path = "simd/sse/unpckhps.rs"]
mod x86_64_simd_sse_unpckhps;
#[path = "simd/sse/unpcklpd.rs"]
mod x86_64_simd_sse_unpcklpd;
#[path = "simd/sse/unpcklps.rs"]
mod x86_64_simd_sse_unpcklps;
#[path = "simd/sse/xorps_xorpd.rs"]
mod x86_64_simd_sse_xorps_xorpd;

// AVX10.1 Tests
#[path = "simd/avx10/bf16.rs"]
mod x86_64_simd_avx10_bf16;
#[path = "simd/avx10/bitalg.rs"]
mod x86_64_simd_avx10_bitalg;
#[path = "simd/avx10/ifma.rs"]
mod x86_64_simd_avx10_ifma;
#[path = "simd/avx10/vbmi.rs"]
mod x86_64_simd_avx10_vbmi;
#[path = "simd/avx10/vnni.rs"]
mod x86_64_simd_avx10_vnni;
#[path = "simd/avx10/vpopcntdq.rs"]
mod x86_64_simd_avx10_vpopcntdq;
#[path = "simd/avx10/ymm_embedded_rounding.rs"]
mod x86_64_simd_avx10_ymm_embedded_rounding;

// AVX10.2 Tests
#[path = "simd/avx10/compare_bf16.rs"]
mod x86_64_simd_avx10_compare_bf16;
#[path = "simd/avx10/copy_sign.rs"]
mod x86_64_simd_avx10_copy_sign;
#[path = "simd/avx10/media_accel.rs"]
mod x86_64_simd_avx10_media_accel;
#[path = "simd/avx10/minmax.rs"]
mod x86_64_simd_avx10_minmax;
#[path = "simd/avx10/saturation_convert.rs"]
mod x86_64_simd_avx10_saturation_convert;
#[path = "simd/avx10/vmpsadbw.rs"]
mod x86_64_simd_avx10_vmpsadbw;

// APX (Advanced Performance Extensions)
#[path = "extensions/apx/ccmp_ctest.rs"]
mod x86_64_apx_ccmp_ctest;
#[path = "extensions/apx/combined.rs"]
mod x86_64_apx_combined;
#[path = "extensions/apx/egpr.rs"]
mod x86_64_apx_egpr;
#[path = "extensions/apx/ndd.rs"]
mod x86_64_apx_ndd;
#[path = "extensions/apx/nf.rs"]
mod x86_64_apx_nf;
#[path = "extensions/apx/push2_pop2.rs"]
mod x86_64_apx_push2_pop2;
#[path = "extensions/apx/rex2.rs"]
mod x86_64_apx_rex2;
#[path = "extensions/apx/zu.rs"]
mod x86_64_apx_zu;

// Stack Operations
#[path = "stack/enter_extended.rs"]
mod x86_64_stack_operations_enter_extended;
#[path = "stack/leave_extended.rs"]
mod x86_64_stack_operations_leave_extended;
#[path = "stack/pop_mem.rs"]
mod x86_64_stack_operations_pop_mem;
#[path = "stack/pop/pop.rs"]
mod x86_64_stack_operations_pop_pop;
#[path = "stack/push_imm.rs"]
mod x86_64_stack_operations_push_imm;
#[path = "stack/push_mem.rs"]
mod x86_64_stack_operations_push_mem;
#[path = "stack/push/push.rs"]
mod x86_64_stack_operations_push_push;
#[path = "stack/pusha_popa.rs"]
mod x86_64_stack_operations_pusha_popa;
#[path = "stack/pushf_popf_extended.rs"]
mod x86_64_stack_operations_pushf_popf_extended;
#[path = "stack/rsp_operations.rs"]
mod x86_64_stack_operations_rsp_operations;
#[path = "stack/stack_alignment.rs"]
mod x86_64_stack_operations_stack_alignment;

// String
#[path = "strings/cmps.rs"]
mod x86_64_string_cmps;
#[path = "strings/lods.rs"]
mod x86_64_string_lods;
#[path = "strings/movs.rs"]
mod x86_64_string_movs;
#[path = "strings/rep_movs.rs"]
mod x86_64_string_rep_movs;
#[path = "strings/rep_stos.rs"]
mod x86_64_string_rep_stos;
#[path = "strings/repe_cmps.rs"]
mod x86_64_string_repe_cmps;
#[path = "strings/repe_scas.rs"]
mod x86_64_string_repe_scas;
#[path = "strings/repne_cmps.rs"]
mod x86_64_string_repne_cmps;
#[path = "strings/repne_scas.rs"]
mod x86_64_string_repne_scas;
#[path = "strings/scas.rs"]
mod x86_64_string_scas;
#[path = "strings/stos.rs"]
mod x86_64_string_stos;
#[path = "strings/string_ops.rs"]
mod x86_64_string_string_ops;

// Sync
#[path = "synchronization/cmpxchg.rs"]
mod x86_64_sync_cmpxchg;
#[path = "synchronization/cmpxchg16b_extended.rs"]
mod x86_64_sync_cmpxchg16b_extended;
#[path = "synchronization/cmpxchg8b_cmpxchg16b.rs"]
mod x86_64_sync_cmpxchg8b_cmpxchg16b;
#[path = "synchronization/cmpxchg8b_extended.rs"]
mod x86_64_sync_cmpxchg8b_extended;
#[path = "synchronization/cmpxchg_extended.rs"]
mod x86_64_sync_cmpxchg_extended;
#[path = "synchronization/lfence_ordering.rs"]
mod x86_64_sync_lfence_ordering;
#[path = "synchronization/lock_prefix.rs"]
mod x86_64_sync_lock_prefix;
#[path = "synchronization/mfence_ordering.rs"]
mod x86_64_sync_mfence_ordering;
#[path = "synchronization/xadd.rs"]
mod x86_64_sync_xadd;
#[path = "synchronization/xadd_extended.rs"]
mod x86_64_sync_xadd_extended;
#[path = "synchronization/xchg_extended.rs"]
mod x86_64_sync_xchg_extended;

// System
#[path = "system/amx.rs"]
mod x86_64_system_amx;
#[path = "system/arpl.rs"]
mod x86_64_system_arpl;
#[path = "system/cache_invalidate.rs"]
mod x86_64_system_cache_invalidate;
#[path = "system/cet.rs"]
mod x86_64_system_cet;
#[path = "system/clac_stac.rs"]
mod x86_64_system_clac_stac;
#[path = "system/clts.rs"]
mod x86_64_system_clts;
#[path = "system/cpuid.rs"]
mod x86_64_system_cpuid;
#[path = "system/fences.rs"]
mod x86_64_system_fences;
#[path = "system/hreset_enqcmd.rs"]
mod x86_64_system_hreset_enqcmd;
#[path = "system/invd_wbinvd_invlpg.rs"]
mod x86_64_system_invd_wbinvd_invlpg;
#[path = "system/invept_invpcid.rs"]
mod x86_64_system_invept_invpcid;
#[path = "system/lar.rs"]
mod x86_64_system_lar;
#[path = "system/lgdt_lidt.rs"]
mod x86_64_system_lgdt_lidt;
#[path = "system/lldt.rs"]
mod x86_64_system_lldt;
#[path = "system/lmsw_smsw.rs"]
mod x86_64_system_lmsw_smsw;
#[path = "system/lsl.rs"]
mod x86_64_system_lsl;
#[path = "system/ltr.rs"]
mod x86_64_system_ltr;
#[path = "system/mmu.rs"]
mod x86_64_system_mmu;
#[path = "system/mov_cr.rs"]
mod x86_64_system_mov_cr;
#[path = "system/mov_dr.rs"]
mod x86_64_system_mov_dr;
#[path = "system/msr_extensions.rs"]
mod x86_64_system_msr_extensions;
#[path = "system/page_fault.rs"]
mod x86_64_system_page_fault;
#[path = "system/protection_keys.rs"]
mod x86_64_system_protection_keys;
#[path = "system/rdfsbase_wrfsbase.rs"]
mod x86_64_system_rdfsbase_wrfsbase;
#[path = "system/rdmsr.rs"]
mod x86_64_system_rdmsr;
#[path = "system/rdpid.rs"]
mod x86_64_system_rdpid;
#[path = "system/rdpkru_wrpkru.rs"]
mod x86_64_system_rdpkru_wrpkru;
#[path = "system/rdpmc.rs"]
mod x86_64_system_rdpmc;
#[path = "system/rdrand.rs"]
mod x86_64_system_rdrand;
#[path = "system/rdseed.rs"]
mod x86_64_system_rdseed;
#[path = "system/rdtsc.rs"]
mod x86_64_system_rdtsc;
#[path = "system/rdtscp.rs"]
mod x86_64_system_rdtscp;
#[path = "system/serialize.rs"]
mod x86_64_system_serialize;
#[path = "system/sgdt_sidt.rs"]
mod x86_64_system_sgdt_sidt;
#[path = "system/sgx.rs"]
mod x86_64_system_sgx;
#[path = "system/sldt.rs"]
mod x86_64_system_sldt;
#[path = "system/specialized.rs"]
mod x86_64_system_specialized;
#[path = "system/str.rs"]
mod x86_64_system_str;
#[path = "system/swapgs.rs"]
mod x86_64_system_swapgs;
#[path = "system/system_management.rs"]
mod x86_64_system_system_management;
#[path = "system/tsx.rs"]
mod x86_64_system_tsx;
#[path = "system/umip.rs"]
mod x86_64_system_umip;
#[path = "system/user_mode_wait.rs"]
mod x86_64_system_user_mode_wait;
#[path = "system/verr_verw.rs"]
mod x86_64_system_verr_verw;
#[path = "system/virtualization.rs"]
mod x86_64_system_virtualization;
#[path = "system/wrmsr.rs"]
mod x86_64_system_wrmsr;
#[path = "system/xsave_extended.rs"]
mod x86_64_system_xsave_extended;

// LAPIC integration tests
#[path = "system/lapic_integration.rs"]
mod x86_64_lapic_integration;

// Regression tests
#[path = "regressions/lazy_flags_compare.rs"]
mod x86_64_regressions_lazy_flags_compare;
#[path = "regressions/lazy_flags_pcmpistri.rs"]
mod x86_64_regressions_lazy_flags_pcmpistri;
