a = source1;
while(true) {
    while(condition) {
        if(random() > 0.5) {
            continue;
        } else {
            break;
        }
    }
    sink(a);
}