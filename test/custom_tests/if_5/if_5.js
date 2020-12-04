a = src1
if (condition1) {
    a = src2
}
else {
    a = sanitizer(a)
}
b = src3
if (condition2) {
    b = src4
}
else {
    b = sanitizer(b)
}
sink = a + b