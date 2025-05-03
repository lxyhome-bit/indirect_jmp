source_filename = "test"
target datalayout = "e-m:e-p:64:64-i64:64-f80:128-n8:16:32:64-S128"

%vtable_3d20_type = type { i64 (i64*)*, i64 (i64*)*, void (i64*)*, void (i64*)* }
%vtable_3d50_type = type { i64 (i64*)*, i64 (i64*)*, void (i64*)*, void (i64*)* }

@global_var_3fd0 = local_unnamed_addr global i64 0
@global_var_2004 = constant [25 x i8] c"Base class show function\00"
@global_var_4040 = global i64 0
@global_var_201d = constant [26 x i8] c"Base class print function\00"
@global_var_2037 = constant [16 x i8] c"Base destructor\00"
@global_var_2047 = constant [28 x i8] c"Derived class show function\00"
@global_var_2063 = constant [19 x i8] c"Derived destructor\00"
@0 = external global i32
@global_var_4150 = local_unnamed_addr global i8 0
@global_var_3d20 = global %vtable_3d20_type { i64 (i64*)* @_ZN7Derived4showEv, i64 (i64*)* @_ZN4Base5printEv, void (i64*)* @_ZN7DerivedD2Ev, void (i64*)* @_ZN7DerivedD0Ev }
@global_var_3d50 = global %vtable_3d50_type { i64 (i64*)* @_ZN4Base4showEv, i64 (i64*)* @_ZN4Base5printEv, void (i64*)* @_ZN4BaseD2Ev, void (i64*)* @_ZN4BaseD0Ev }

define i64 @_init() local_unnamed_addr {
dec_label_pc_1000:
  %rax.0.reg2mem = alloca i64, !insn.addr !0
  %0 = load i64, i64* inttoptr (i64 16368 to i64*), align 16, !insn.addr !1
  %1 = icmp eq i64 %0, 0, !insn.addr !2
  store i64 0, i64* %rax.0.reg2mem, !insn.addr !3
  br i1 %1, label %dec_label_pc_1016, label %dec_label_pc_1014, !insn.addr !3

dec_label_pc_1014:                                ; preds = %dec_label_pc_1000
  call void @__gmon_start__(), !insn.addr !4
  store i64 ptrtoint (i32* @0 to i64), i64* %rax.0.reg2mem, !insn.addr !4
  br label %dec_label_pc_1016, !insn.addr !4

dec_label_pc_1016:                                ; preds = %dec_label_pc_1014, %dec_label_pc_1000
  %rax.0.reload = load i64, i64* %rax.0.reg2mem
  ret i64 %rax.0.reload, !insn.addr !5
}

define void @function_1070(i64* %d) local_unnamed_addr {
dec_label_pc_1070:
  call void @__cxa_finalize(i64* %d), !insn.addr !6
  ret void, !insn.addr !6
}

define i64 @function_1080(i64* %arg1, i8* %arg2) local_unnamed_addr {
dec_label_pc_1080:
  %0 = call i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64* %arg1, i8* %arg2), !insn.addr !7
  ret i64 %0, !insn.addr !7
}

define i64 @function_1090(i64 %arg1) local_unnamed_addr {
dec_label_pc_1090:
  %0 = call i64 @_Znwm(i64 %arg1), !insn.addr !8
  ret i64 %0, !insn.addr !8
}

define i64 @function_10a0(i64* %arg1, i64 %arg2) local_unnamed_addr {
dec_label_pc_10a0:
  %0 = call i64 @_ZdlPvm(i64* %arg1, i64 %arg2), !insn.addr !9
  ret i64 %0, !insn.addr !9
}

define i64 @function_10b0(i64* (i64*)* %arg1) local_unnamed_addr {
dec_label_pc_10b0:
  %0 = call i64 @_ZNSolsEPFRSoS_E(i64* (i64*)* %arg1), !insn.addr !10
  ret i64 %0, !insn.addr !10
}

define i64 @_start(i64 %arg1, i64 %arg2, i64 %arg3, i64 %arg4, i64 %arg5, i64 %arg6) local_unnamed_addr {
dec_label_pc_10c0:
  %stack_var_8 = alloca i64, align 8
  %0 = trunc i64 %arg6 to i32, !insn.addr !11
  %1 = bitcast i64* %stack_var_8 to i8**, !insn.addr !11
  %2 = inttoptr i64 %arg3 to void ()*, !insn.addr !11
  %3 = call i32 @__libc_start_main(i64 4521, i32 %0, i8** nonnull %1, void ()* null, void ()* null, void ()* %2), !insn.addr !11
  %4 = call i64 @__asm_hlt(), !insn.addr !12
  unreachable, !insn.addr !12
}

define i64 @deregister_tm_clones() local_unnamed_addr {
dec_label_pc_10f0:
  ret i64 16408, !insn.addr !13
}

define i64 @register_tm_clones() local_unnamed_addr {
dec_label_pc_1120:
  ret i64 0, !insn.addr !14
}

define i64 @__do_global_dtors_aux() local_unnamed_addr {
dec_label_pc_1160:
  %0 = alloca i64
  %1 = load i64, i64* %0
  %2 = load i8, i8* @global_var_4150, align 1, !insn.addr !15
  %3 = icmp eq i8 %2, 0, !insn.addr !15
  %4 = icmp eq i1 %3, false, !insn.addr !16
  br i1 %4, label %dec_label_pc_1198, label %dec_label_pc_116d, !insn.addr !16

dec_label_pc_116d:                                ; preds = %dec_label_pc_1160
  %5 = load i64, i64* @global_var_3fd0, align 8, !insn.addr !17
  %6 = icmp eq i64 %5, 0, !insn.addr !17
  br i1 %6, label %dec_label_pc_1187, label %dec_label_pc_117b, !insn.addr !18

dec_label_pc_117b:                                ; preds = %dec_label_pc_116d
  %7 = load i64, i64* inttoptr (i64 16392 to i64*), align 8, !insn.addr !19
  %8 = inttoptr i64 %7 to i64*, !insn.addr !20
  call void @__cxa_finalize(i64* %8), !insn.addr !20
  br label %dec_label_pc_1187, !insn.addr !20

dec_label_pc_1187:                                ; preds = %dec_label_pc_117b, %dec_label_pc_116d
  %9 = call i64 @deregister_tm_clones(), !insn.addr !21
  store i8 1, i8* @global_var_4150, align 1, !insn.addr !22
  ret i64 %9, !insn.addr !23

dec_label_pc_1198:                                ; preds = %dec_label_pc_1160
  ret i64 %1, !insn.addr !24

; uselistorder directives
  uselistorder i8 0, { 1, 0 }
  uselistorder i8* @global_var_4150, { 1, 0 }
}

define i64 @frame_dummy() local_unnamed_addr {
dec_label_pc_11a0:
  %0 = call i64 @register_tm_clones(), !insn.addr !25
  ret i64 %0, !insn.addr !25
}

define i32 @main() local_unnamed_addr {
dec_label_pc_11a9:
  %0 = call i64 @_Znwm(i64 8), !insn.addr !26
  %1 = inttoptr i64 %0 to i64*, !insn.addr !27
  store i64 0, i64* %1, align 8, !insn.addr !27
  call void @_ZN7DerivedC2Ev(i64* %1), !insn.addr !28
  %2 = call i64 @_Znwm(i64 8), !insn.addr !29
  %3 = inttoptr i64 %2 to i64*, !insn.addr !30
  store i64 0, i64* %3, align 8, !insn.addr !30
  call void @_ZN7DerivedC2Ev(i64* %3), !insn.addr !31
  %4 = call i64 @_Znwm(i64 8), !insn.addr !32
  %5 = inttoptr i64 %4 to i64*, !insn.addr !33
  store i64 0, i64* %5, align 8, !insn.addr !33
  call void @_ZN4BaseC2Ev(i64* %5), !insn.addr !34
  ret i32 0, !insn.addr !35

; uselistorder directives
  uselistorder void (i64*)* @_ZN7DerivedC2Ev, { 1, 0 }
  uselistorder i64 (i64)* @_Znwm, { 2, 1, 0, 3 }
}

define i64 @_ZN4Base4showEv(i64* %result) {
dec_label_pc_12b8:
  %0 = call i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64* nonnull @global_var_4040, i8* getelementptr inbounds ([25 x i8], [25 x i8]* @global_var_2004, i64 0, i64 0)), !insn.addr !36
  %1 = inttoptr i64 %0 to i64* (i64*)*, !insn.addr !37
  %2 = call i64 @_ZNSolsEPFRSoS_E(i64* (i64*)* %1), !insn.addr !37
  ret i64 %2, !insn.addr !38
}

define i64 @_ZN4Base5printEv(i64* %result) {
dec_label_pc_12f6:
  %0 = call i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64* nonnull @global_var_4040, i8* getelementptr inbounds ([26 x i8], [26 x i8]* @global_var_201d, i64 0, i64 0)), !insn.addr !39
  %1 = inttoptr i64 %0 to i64* (i64*)*, !insn.addr !40
  %2 = call i64 @_ZNSolsEPFRSoS_E(i64* (i64*)* %1), !insn.addr !40
  ret i64 %2, !insn.addr !41
}

define void @_ZN4BaseD2Ev(i64* %result) {
dec_label_pc_1334:
  store i64 ptrtoint (%vtable_3d50_type* @global_var_3d50 to i64), i64* %result, align 8, !insn.addr !42
  %0 = call i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64* nonnull @global_var_4040, i8* getelementptr inbounds ([16 x i8], [16 x i8]* @global_var_2037, i64 0, i64 0)), !insn.addr !43
  %1 = inttoptr i64 %0 to i64* (i64*)*, !insn.addr !44
  %2 = call i64 @_ZNSolsEPFRSoS_E(i64* (i64*)* %1), !insn.addr !44
  ret void, !insn.addr !45
}

define void @_ZN4BaseD0Ev(i64* %result) {
dec_label_pc_1380:
  call void @_ZN4BaseD2Ev(i64* %result), !insn.addr !46
  %0 = call i64 @_ZdlPvm(i64* %result, i64 8), !insn.addr !47
  ret void, !insn.addr !48
}

define i64 @_ZN7Derived4showEv(i64* %result) {
dec_label_pc_13b0:
  %0 = call i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64* nonnull @global_var_4040, i8* getelementptr inbounds ([28 x i8], [28 x i8]* @global_var_2047, i64 0, i64 0)), !insn.addr !49
  %1 = inttoptr i64 %0 to i64* (i64*)*, !insn.addr !50
  %2 = call i64 @_ZNSolsEPFRSoS_E(i64* (i64*)* %1), !insn.addr !50
  ret i64 %2, !insn.addr !51
}

define void @_ZN7DerivedD2Ev(i64* %result) {
dec_label_pc_13ee:
  store i64 ptrtoint (%vtable_3d20_type* @global_var_3d20 to i64), i64* %result, align 8, !insn.addr !52
  %0 = call i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64* nonnull @global_var_4040, i8* getelementptr inbounds ([19 x i8], [19 x i8]* @global_var_2063, i64 0, i64 0)), !insn.addr !53
  %1 = inttoptr i64 %0 to i64* (i64*)*, !insn.addr !54
  %2 = call i64 @_ZNSolsEPFRSoS_E(i64* (i64*)* %1), !insn.addr !54
  call void @_ZN4BaseD2Ev(i64* %result), !insn.addr !55
  ret void, !insn.addr !56

; uselistorder directives
  uselistorder i64 (i64* (i64*)*)* @_ZNSolsEPFRSoS_E, { 1, 4, 0, 3, 2, 5 }
  uselistorder i64 (i64*, i8*)* @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc, { 1, 4, 0, 3, 2, 5 }
  uselistorder i64 0, { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 14, 1, 0, 15, 12, 13 }
}

define void @_ZN7DerivedD0Ev(i64* %result) {
dec_label_pc_1446:
  call void @_ZN7DerivedD2Ev(i64* %result), !insn.addr !57
  %0 = call i64 @_ZdlPvm(i64* %result, i64 8), !insn.addr !58
  ret void, !insn.addr !59

; uselistorder directives
  uselistorder i64 (i64*, i64)* @_ZdlPvm, { 1, 0, 2 }
}

define void @_ZN4BaseC2Ev(i64* %result) local_unnamed_addr {
dec_label_pc_1476:
  store i64 ptrtoint (%vtable_3d50_type* @global_var_3d50 to i64), i64* %result, align 8, !insn.addr !60
  ret void, !insn.addr !61

; uselistorder directives
  uselistorder void (i64*)* @_ZN4BaseD2Ev, { 2, 1, 0 }
  uselistorder i64 ptrtoint (%vtable_3d50_type* @global_var_3d50 to i64), { 1, 0 }
}

define void @_ZN7DerivedC2Ev(i64* %result) local_unnamed_addr {
dec_label_pc_1494:
  call void @_ZN4BaseC2Ev(i64* %result), !insn.addr !62
  store i64 ptrtoint (%vtable_3d20_type* @global_var_3d20 to i64), i64* %result, align 8, !insn.addr !63
  ret void, !insn.addr !64

; uselistorder directives
  uselistorder void (i64*)* @_ZN7DerivedD2Ev, { 1, 0 }
  uselistorder i64 ptrtoint (%vtable_3d20_type* @global_var_3d20 to i64), { 1, 0 }
  uselistorder void (i64*)* @_ZN4BaseC2Ev, { 1, 0 }
}

define i64 @_fini() local_unnamed_addr {
dec_label_pc_14c4:
  %0 = alloca i64
  %1 = load i64, i64* %0
  ret i64 %1, !insn.addr !65

; uselistorder directives
  uselistorder i32 1, { 1, 0, 3, 2 }
}

declare i64 @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(i64*, i8*) local_unnamed_addr

declare i64 @_Znwm(i64) local_unnamed_addr

declare i64 @_ZdlPvm(i64*, i64) local_unnamed_addr

declare i64 @_ZNSolsEPFRSoS_E(i64* (i64*)*) local_unnamed_addr

declare void @__cxa_finalize(i64*) local_unnamed_addr

declare i32 @__libc_start_main(i64, i32, i8**, void ()*, void ()*, void ()*) local_unnamed_addr

declare void @__gmon_start__() local_unnamed_addr

declare i64 @__asm_hlt() local_unnamed_addr

!0 = !{i64 4096}
!1 = !{i64 4104}
!2 = !{i64 4111}
!3 = !{i64 4114}
!4 = !{i64 4116}
!5 = !{i64 4122}
!6 = !{i64 4212}
!7 = !{i64 4228}
!8 = !{i64 4244}
!9 = !{i64 4260}
!10 = !{i64 4276}
!11 = !{i64 4319}
!12 = !{i64 4325}
!13 = !{i64 4376}
!14 = !{i64 4440}
!15 = !{i64 4452}
!16 = !{i64 4459}
!17 = !{i64 4462}
!18 = !{i64 4473}
!19 = !{i64 4475}
!20 = !{i64 4482}
!21 = !{i64 4487}
!22 = !{i64 4492}
!23 = !{i64 4500}
!24 = !{i64 4504}
!25 = !{i64 4516}
!26 = !{i64 4539}
!27 = !{i64 4547}
!28 = !{i64 4557}
!29 = !{i64 4571}
!30 = !{i64 4579}
!31 = !{i64 4589}
!32 = !{i64 4603}
!33 = !{i64 4611}
!34 = !{i64 4621}
!35 = !{i64 4790}
!36 = !{i64 4828}
!37 = !{i64 4846}
!38 = !{i64 4853}
!39 = !{i64 4890}
!40 = !{i64 4908}
!41 = !{i64 4915}
!42 = !{i64 4943}
!43 = !{i64 4966}
!44 = !{i64 4984}
!45 = !{i64 4991}
!46 = !{i64 5015}
!47 = !{i64 5032}
!48 = !{i64 5038}
!49 = !{i64 5076}
!50 = !{i64 5094}
!51 = !{i64 5101}
!52 = !{i64 5129}
!53 = !{i64 5152}
!54 = !{i64 5170}
!55 = !{i64 5182}
!56 = !{i64 5189}
!57 = !{i64 5213}
!58 = !{i64 5230}
!59 = !{i64 5236}
!60 = !{i64 5261}
!61 = !{i64 5266}
!62 = !{i64 5291}
!63 = !{i64 5307}
!64 = !{i64 5312}
!65 = !{i64 5328}
