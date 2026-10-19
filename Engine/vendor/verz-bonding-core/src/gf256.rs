//! Arithmetic in GF(2^8) with the polynomial x^8 + x^4 + x^3 + x^2 + 1.

const POLY: u16 = 0x11d;

const fn tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0_u8; 512];
    let mut log = [0_u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = tables();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "zero has no inverse");
    EXP[255 - LOG[a as usize] as usize]
}

/// `dst ^= c * src`, element-wise.
pub fn mul_add(dst: &mut [u8], src: &[u8], c: u8) {
    debug_assert_eq!(dst.len(), src.len());
    match c {
        0 => {}
        1 => dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= s),
        _ => {
            let mut row = [0_u8; 256];
            for (x, slot) in row.iter_mut().enumerate() {
                *slot = mul(c, x as u8);
            }
            dst.iter_mut()
                .zip(src)
                .for_each(|(d, s)| *d ^= row[*s as usize]);
        }
    }
}

/// `dst = c * dst`, element-wise.
pub fn scale(dst: &mut [u8], c: u8) {
    if c == 1 {
        return;
    }
    dst.iter_mut().for_each(|d| *d = mul(*d, c));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for a in 1..=255_u8 {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }

    #[test]
    fn multiplication_distributes_over_addition() {
        for a in [3_u8, 29, 200] {
            for b in 0..=255_u8 {
                for c in [0_u8, 1, 77, 255] {
                    assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                }
            }
        }
    }
}
