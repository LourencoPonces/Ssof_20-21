a=source('nis');
while (true) {
    if(x==10){
        a = sanitizer(a,1);
        break;
    }
    x++;
}
q=sink(a);