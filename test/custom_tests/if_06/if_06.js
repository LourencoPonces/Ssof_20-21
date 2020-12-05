if (condition1) {
    if (condition2) {
        a = src1
    }
    else {
        a = src2
    }
    a = sanitizer(a)
}
else {
    if (condition3) {
        a = src3
    }
    else {
        a = src4
    }   
}
sink = a