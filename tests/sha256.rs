#![cfg(test)]

use hex::FromHex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use xbits::FromBits;

/// test sha256, xbits
/// test data from: <https://iancoleman.io/bip39>
#[test]
fn test_checksum() {
    // <https://iancoleman.io/bip39>
    let test_data = &[
        (
            "4475f031a327af4f6ffa7fe879bc3233",
            "547, 1404, 99, 562, 983, 1341, 1535, 639, 1859, 1647, 100, 826",
            0b1010_0000,
        ),
        (
            "cfe8aabe8954a2175feb284a10b9e17c4a6f207a",
            "1663, 554, 1405, 149, 593, 93, 1021, 808, 592, 1070, 962, 1988, 1335, 1153, 1873",
            0b1000_1000,
        ),
        (
            "a07a327fa5e2c52f0e81d35e4acc9a6df2ef86f70e057ed7",
            "1283, 1676, 1279, 606, 354, 1212, 464, 467, 754, 691, 308, 1759, 375, 1563, 1761, 1541, 1014, 1485",
            0b0011_0100,
        ),
        (
            "d73c689c0e98e883d481bc9d3a011cb19e6f28f6ebf733e9c46cdb16",
            "1721, 1818, 312, 233, 1140, 527, 656, 444, 1257, 1664, 569, 793, 1847, 1187, 1757, 1015, 415, 625, 217, 1457, 805",
            0b0100_1010,
        ),
        (
            "1d54fd71dec06cad1f170481da1655d17fdf396eea112f83dd93fbb2e0644d4c",
            "234, 1343, 739, 1516, 54, 692, 994, 1796, 1038, 1669, 1195, 1303, 2031, 1253, 1501, 529, 380, 247, 807, 1979, 368, 401, 425, 1054",
            0b0001_1110,
        ),
    ];

    for (e, s, check) in test_data {
        let (entropy, indices): (Vec<u8>, Vec<usize>) = (
            Vec::from_hex(e).unwrap(),
            s.split(',').map(|x| x.trim().parse().unwrap()).collect(),
        );

        let check_mask = BTreeMap::<usize, u8>::from([
            (12, 0b1111_0000),
            (15, 0b1111_1000),
            (18, 0b1111_1100),
            (21, 0b1111_1110),
            (24, 0b1111_1111),
        ])[&(indices.len())];

        let mut indices_data = Vec::from_bits_chunk(indices.into_iter(), 11);
        let tail = indices_data.pop().unwrap();
        let checksum = Sha256::digest(&indices_data)[0];

        assert_eq!(*entropy, indices_data, "{e}");
        assert_eq!(checksum & check_mask, *check, "{e}");
        assert_eq!(*check & check_mask, tail, "{e}");
    }
}
