"""Independent LLVM IR witness generator, not a SMIR compiler backend."""


def expanded_powi(width=64):
    if type(width) is not int or not 1 <= width <= 2**23:
        raise ValueError('power exponent width')
    # Source deferred poison must not turn into a branch-UB solely because the
    # algorithm uses exponent-controlled loops. Freeze once before control use.
    function = '''define internal double @portable_powi64(double %x, i64 %input) {
entry:
  %n = freeze i64 %input
  %negative = icmp slt i64 %n, 0
  %absnegative = sub i64 0, %n
  %magnitude = select i1 %negative, i64 %absnegative, i64 %n
  br label %loop
loop:
  %remaining = phi i64 [ %magnitude, %entry ], [ %half, %step ]
  %result = phi double [ 1.0, %entry ], [ %nextresult, %step ]
  %base = phi double [ %x, %entry ], [ %square, %step ]
  %done = icmp eq i64 %remaining, 0
  br i1 %done, label %exit, label %step
step:
  %lowbit = and i64 %remaining, 1
  %odd = icmp ne i64 %lowbit, 0
  %product = fmul double %result, %base
  %nextresult = select i1 %odd, double %product, double %result
  %square = fmul double %base, %base
  %half = lshr i64 %remaining, 1
  br label %loop
exit:
  %inverse = fdiv double 1.0, %result
  %answer = select i1 %negative, double %inverse, double %result
  ret double %answer
}
'''
    function = function.replace('@portable_powi64', '@portable_powi' + str(width)).replace('i64', 'i' + str(width))
    if width == 1:
        function = function.replace('%half = lshr i1 %remaining, 1', '%half = and i1 %remaining, 0')
    return function


def expanded_powi64():
    return expanded_powi(64) + '''
define i32 @main() {
  %wide = call double @portable_powi64(double 2.0, i64 4294967296)
  %infinite = fcmp oeq double %wide, 0x7FF0000000000000
  %parity = call double @portable_powi64(double -1.0, i64 -9223372036854775808)
  %even = fcmp oeq double %parity, 1.0
  %normal = call double @portable_powi64(double 2.0, i64 3)
  %eight = fcmp oeq double %normal, 8.0
  %negwide = call double @portable_powi64(double 2.0, i64 -4294967296)
  %underflow = fcmp oeq double %negwide, 0.0
  %minimum = call double @portable_powi64(double 2.0, i64 -9223372036854775808)
  %minzero = fcmp oeq double %minimum, 0.0
  %oddwide = call double @portable_powi64(double -1.0, i64 4294967297)
  %odd = fcmp oeq double %oddwide, -1.0
  %zeroexp = call double @portable_powi64(double 0.0, i64 0)
  %one = fcmp oeq double %zeroexp, 1.0
  %first = and i1 %infinite, %even
  %second = and i1 %eight, %underflow
  %third = and i1 %minzero, %odd
  %part = and i1 %first, %second
  %rest = and i1 %third, %one
  %ok = and i1 %part, %rest
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}
'''
