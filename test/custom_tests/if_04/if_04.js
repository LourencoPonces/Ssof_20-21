a = src1
if (condition1) {
    a = src2
}
else {
    a = sanitizer(a)
}
if (condition2) {
    b = sink
}
else {
    b = sanitizer(b)
}
b = a