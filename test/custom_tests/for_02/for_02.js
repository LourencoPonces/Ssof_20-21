a = src1;
for(i = src2; condition; i++) {
    if(test) {
        a = a + i;
        break;
    } else {
        a = sanitizer(a);
    }
}
sink(a);