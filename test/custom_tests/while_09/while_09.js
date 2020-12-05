a=src1('nis');
c="";
d1="";
d2="";
d3="";
while (e == "") {
    c = c + d3;
    d3 = d2;
    d2 = d1;
    d1 = a;
    a = src2(a,1);
}
snk2=snk1(c);