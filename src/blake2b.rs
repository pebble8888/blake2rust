pub const BLAKE2B_BLOCKBYTES: usize = 128;
pub const BLAKE2B_KEYBYTES: usize = 64;
pub const BLAKE2B_OUTBYTES: usize = 64;
pub const BLAKE2B_SALTBYTES: usize = 16;
pub const BLAKE2B_PERSONALBYTES: usize = 16;

#[derive(Copy, Clone)]
pub struct Blake2bState {
    pub h: [u64; 8],
    pub t: [u64; 2],
    pub f: [u64; 2],
    pub buf: [u8; BLAKE2B_BLOCKBYTES],
    pub buflen: usize,
    pub outlen: usize,
    pub last_node: u8,
}

pub struct Blake2bParam {
    pub digest_length: u8,
    pub key_length: u8,
    pub fanout: u8,
    pub depth: u8,
    pub leaf_length: u32,
    pub node_offset: u32,
    pub xof_length: u32,
    pub node_depth: u8,
    pub inner_length: u8,
    pub reserved: [u8; 14],
    pub salt: [u8; BLAKE2B_SALTBYTES],
    pub personal: [u8; BLAKE2B_PERSONALBYTES],
}

impl Blake2bParam {
    pub fn to_u64(&self, index: usize) -> u64 {
        match index {
            0 => load64(&[self.digest_length,
                          self.key_length,
                          self.fanout,
                          self.depth,
                          le32(self.leaf_length)[0],
                          le32(self.leaf_length)[1],
                          le32(self.leaf_length)[2],
                          le32(self.leaf_length)[3]]),
            1 => load64(&[le32(self.node_offset)[0],
                          le32(self.node_offset)[1],
                          le32(self.node_offset)[2],
                          le32(self.node_offset)[3],
                          le32(self.xof_length)[0],
                          le32(self.xof_length)[1],
                          le32(self.xof_length)[2],
                          le32(self.xof_length)[3]]),
            2 => load64(&[self.node_depth,
                          self.inner_length,
                          self.reserved[0],
                          self.reserved[1],
                          self.reserved[2],
                          self.reserved[3],
                          self.reserved[4],
                          self.reserved[5]]),
            3 => load64(&self.reserved[6..14]),
            4 => load64(&self.salt[0..8]),
            5 => load64(&self.salt[8..16]),
            6 => load64(&self.personal[0..8]),
            7 => load64(&self.personal[8..16]),
            _ => { assert!(false); return 0; }
        }
    }
}

pub fn blake2b_init_param(s: &mut Blake2bState, p: &Blake2bParam) -> bool
{
    for i in 0..(BLAKE2B_OUTBYTES/8) {
        s.h[i] = BLAKE2B_IV[i] ^ p.to_u64(i);
    }
    s.outlen = p.digest_length as usize;
    true
}

pub fn blake2b_update(s: &mut Blake2bState, pin: &[u8], a_inlen: usize) -> bool
{
    let mut inlen = a_inlen;
    let mut j = 0;
    if inlen > 0 {
        let left = s.buflen;
        let fill = BLAKE2B_BLOCKBYTES - left;
        if inlen > fill {
            s.buflen = 0;

            for i in 0..fill {
                s.buf[left+i] = pin[j+i];
            }

            blake2b_increment_counter(&mut s.t, BLAKE2B_BLOCKBYTES as u64);
            blake2b_compress(&mut s.h, &s.t, &s.f, &s.buf);

            j = j + fill;
            inlen = inlen - fill;
            while inlen > BLAKE2B_BLOCKBYTES {
                blake2b_increment_counter(&mut s.t, BLAKE2B_BLOCKBYTES as u64);
                blake2b_compress(&mut s.h, &s.t, &s.f, &pin[j..j+BLAKE2B_BLOCKBYTES]);
                j = j + BLAKE2B_BLOCKBYTES;
                inlen = inlen - BLAKE2B_BLOCKBYTES;
            }
        }

        for i in 0..inlen {
            s.buf[s.buflen+i] = pin[j+i];
        }

        s.buflen = s.buflen + inlen;
    }
    true
}

pub fn blake2b_final(s: &mut Blake2bState, out: &mut[u8], outlen: usize) -> bool
{
    let mut buffer = [0; BLAKE2B_OUTBYTES];

    if outlen < s.outlen {
        return false;
    }
    if blake2b_is_lastblock(s) {
        return false;
    }

    blake2b_increment_counter(&mut s.t, s.buflen as u64);
    blake2b_set_lastblock(s);
    // padding
    let len = BLAKE2B_BLOCKBYTES - s.buflen;
    for i in 0..len {
        s.buf[s.buflen+i] = 0;
    }

    blake2b_compress(&mut s.h, &s.t, &s.f, &s.buf);

    for i in 0..(s.outlen/8) {
        set_le64(&mut buffer[(i*8)..(i*8+8)], s.h[i]);
    }

    for i in 0..(s.outlen) {
        out[i] = buffer[i];
    }
    for i in 0..BLAKE2B_OUTBYTES {
        buffer[i] = 0;
    }
    return true;
}

pub fn secure_zero_memory(v: &mut [u8], n: usize)
{
    for i in 0..n {
        v[i] = 0;
    }
}

fn blake2b_set_lastnode(s: &mut Blake2bState)
{
    s.f[1] = std::u64::MAX;
}

fn blake2b_is_lastblock(s: &Blake2bState) -> bool
{
    return s.f[0] != 0;
}

fn blake2b_set_lastblock(s: &mut Blake2bState)
{
    if s.last_node != 0 {
        blake2b_set_lastnode(s);
    }
    s.f[0] = std::u64::MAX;
}

fn blake2b_increment_counter(st: &mut [u64; 2], inc: u64)
{
    st[0] = st[0] + inc;
    let val;
    if st[0] < inc {
        val = 1;
    } else {
        val = 0;
    }
    st[1] = st[1] + val;
}

fn set_le64(out: &mut [u8], v: u64)
{
    out[0] = (v & 0xff) as u8;
    out[1] = ((v >> 8) & 0xff) as u8;  
    out[2] = ((v >> 16) & 0xff) as u8;
    out[3] = ((v >> 24) & 0xff) as u8;
    out[4] = ((v >> 32) & 0xff) as u8;
    out[5] = ((v >> 40) & 0xff) as u8;
    out[6] = ((v >> 48) & 0xff) as u8;
    out[7] = ((v >> 56) & 0xff) as u8;
}

fn le32(v: u32) -> [u8; 4]
{
    [
        (v & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 24) & 0xff) as u8,
    ]
}

fn load64(v: &[u8]) -> u64
{
    ((v[0] as u64) <<  0) |
    ((v[1] as u64) <<  8) |
    ((v[2] as u64) << 16) |
    ((v[3] as u64) << 24) |
    ((v[4] as u64) << 32) |
    ((v[5] as u64) << 40) |
    ((v[6] as u64) << 48) |
    ((v[7] as u64) << 56)
}

fn g(r: usize, i: usize, v: &mut [u64], pat: [usize; 4], m: &[u64])
{
    v[pat[0]] = v[pat[0]].wrapping_add(v[pat[1]]).wrapping_add(m[BLAKE2B_SIGMA[r][2*i+0]]);
    v[pat[3]] = rotr64(v[pat[3]] ^ v[pat[0]], 32);
    v[pat[2]] = v[pat[2]].wrapping_add(v[pat[3]]);
    v[pat[1]] = rotr64(v[pat[1]] ^ v[pat[2]], 24);
    v[pat[0]] = v[pat[0]].wrapping_add(v[pat[1]]).wrapping_add(m[BLAKE2B_SIGMA[r][2*i+1]]);
    v[pat[3]] = rotr64(v[pat[3]] ^ v[pat[0]], 16);
    v[pat[2]] = v[pat[2]].wrapping_add(v[pat[3]]);
    v[pat[1]] = rotr64(v[pat[1]] ^ v[pat[2]], 63);
}

fn rotr64(w: u64, c: usize) -> u64
{
    return w.wrapping_shr(c as u32) | w.wrapping_shl((64 - c) as u32);
}

fn round(r: usize, v: &mut [u64], m: &[u64])
{
    g(r, 0, v, [ 0,  4,  8, 12], m);
    g(r, 1, v, [ 1,  5,  9, 13], m);
    g(r, 2, v, [ 2,  6, 10, 14], m);
    g(r, 3, v, [ 3,  7, 11, 15], m);
    g(r, 4, v, [ 0,  5, 10, 15], m);
    g(r, 5, v, [ 1,  6, 11, 12], m);
    g(r, 6, v, [ 2,  7,  8, 13], m);
    g(r, 7, v, [ 3,  4,  9, 14], m);
}

fn blake2b_compress(sh: &mut [u64; 8], st: &[u64; 2], sf: &[u64; 2], block: &[u8])
{
    let mut m = [0u64; 16];
    let mut v = [0u64; 16];

    for i in 0..16 {
        m[i] = load64(&block[(i*8)..(i*8+8)]);
    }

    for i in 0..8 {
        v[i] = sh[i];
    }
    v[ 8] = BLAKE2B_IV[0];
    v[ 9] = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];
    v[12] = BLAKE2B_IV[4] ^ st[0];
    v[13] = BLAKE2B_IV[5] ^ st[1];
    v[14] = BLAKE2B_IV[6] ^ sf[0];
    v[15] = BLAKE2B_IV[7] ^ sf[1];

    round(0, &mut v, &m);
    round(1, &mut v, &m);
    round(2, &mut v, &m);
    round(3, &mut v, &m);
    round(4, &mut v, &m);
    round(5, &mut v, &m);
    round(6, &mut v, &m);
    round(7, &mut v, &m);
    round(8, &mut v, &m);
    round(9, &mut v, &m);
    round(10, &mut v, &m);
    round(11, &mut v, &m);

    for i in 0..8 {
        sh[i] = sh[i] ^ v[i] ^ v[i + 8];
    }
}

const BLAKE2B_IV: [u64; 8] =
[
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = 
[
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
];

