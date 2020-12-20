void p4Save(String filename) {
    save(filename);
    if (PASSTHRU) {
        System.out.println(filename);
    }
    exit();
}
