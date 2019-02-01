#[test]
fn blake2bp_test() {
    let x = 123;
    assert!(x == 123);

    let mut key = [0u8; blake2rust::blake2b::BLAKE2B_KEYBYTES];
    let mut buf = [0u8; blake2rust::blake2bp::BLAKE2_KAT_LENGTH];
    for i in 0..key.len() {
        key[i] = i as u8;
    }
    for i in 0..buf.len() {
        buf[i] = i as u8;
    }
    for i in 0..blake2rust::blake2bp::BLAKE2_KAT_LENGTH {
        let mut hash = [0u8; blake2rust::blake2b::BLAKE2B_OUTBYTES];
        blake2rust::blake2bp::blake2bp(&mut hash, blake2rust::blake2b::BLAKE2B_OUTBYTES, &buf, i, &key, blake2rust::blake2b::BLAKE2B_KEYBYTES);
        for j in 0..blake2rust::blake2b::BLAKE2B_OUTBYTES {
            assert_eq!(hash[j], blake2rust::blake2bp::BLAKE2BP_KEYED_KAT[i][j]);
        }
    }
}

