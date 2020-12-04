if (condition1) {
    if (condition2) {
        if (condition3) {
            a = src1
        }
        else {
            a = src2
        }
    }
    else {
        if (condition4) {
            a = src3
        }
        else {
            a = src4
        }
    }
    a = sanitizer(a)
}
else {
    if (condition5) {
        if (condition6) {
            a = src5
        }
        else {
            a = src6
        }
    }
    else {
        if (condition7) {
            a = src7
        }
        else {
            a = src8
        }
    }   
}
sink = a