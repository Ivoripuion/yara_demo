rule test {
    meta:
        KEY = "test"
    strings:
        $s1 = "tesaaaaaaaaaaaaaaaaaaaaaaaaaaat"
    condition:
        any of them
}
