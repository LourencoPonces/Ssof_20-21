a = src1;
for(let i = 0; condition; i++) {
    a = sanitizer(a);
}
sink(a);