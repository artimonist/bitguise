#![cfg(test)]
use std::str::FromStr;

use disguise::Mnemonic;
use hex::FromHex;
use itertools::join;

#[test]
fn test_mnemonic() {
    const TEST_DATA: &[&str] = &[
        // english
        "24bedf02898de83bf1352918406540b3",
        "293, 1975, 1541, 152, 1780, 239, 1574, 1321, 194, 25, 641, 827",
        "caution want scheme basic teach bulb shadow pioneer blue add expand guess",
        // japanese
        "9346406629fa1cce46ddedf07aa8c2acf04d5daf",
        "1178, 400, 204, 671, 1294, 825, 219, 1517, 1923, 1706, 389, 719, 38, 1398, 1531",
        "ちきん　ぎじかがく　うわさ　ごますり　てみじか　しまう　えがく　のっく　やめる　ぶどう　ききて　さかみち　あゆむ　ならう　はあく",
        // español
        "1838fb9458b49757bd8d517c9ef73139c1be70253ca11884",
        "193, 1598, 1832, 1419, 587, 1374, 1969, 1361, 996, 1981, 1634, 924, 223, 448, 1191, 1185, 196, 318",
        "avance res teoría perro editor parque vecino pánico leche vengar rojizo instante barba contar muela mover avellana calle",
        // chinese simplified
        "97a000e094f0c0eee5baa44af217683015275ad21e847c1c82db392b",
        "1213, 0, 449, 335, 96, 955, 1207, 676, 599, 1157, 1744, 769, 659, 1387, 579, 1668, 992, 1824, 1462, 914, 1429",
        "婚 的 候 声 点 跳 盛 超 犯 炮 厅 湖 述 拥 续 羊 伊 坑 敬 编 梅",
        // french
        "31aec95cb3228b38960e17708fe1b395b4e336bc0cfe072f31b0144cd49d1ed7",
        "397, 946, 697, 818, 325, 1250, 705, 1559, 900, 1016, 871, 347, 625, 1242, 1921, 1278, 57, 972, 864, 324, 1642, 628, 986, 1951",
        "circuler grotte épargne fictif canon mince épisode propre gélule immuable frère caution écureuil miauler trilogie mousson affreux hérisson frapper caneton reptile effacer honorer uranium",
    ];

    for i in (0..TEST_DATA.len()).step_by(3) {
        let (entropy, indices_str, mnemonic_str) = (
            Vec::from_hex(TEST_DATA[i]).unwrap(),
            TEST_DATA[i + 1],
            TEST_DATA[i + 2],
        );

        let language = Mnemonic::detect_language(mnemonic_str.split_whitespace())[0];
        let mnemonic_entropy = Mnemonic::new(&entropy, language).unwrap();
        let mnemonic_retrieve = Mnemonic::from_str(mnemonic_str).unwrap();

        assert_eq!(mnemonic_entropy, mnemonic_retrieve);
        assert_eq!(join(mnemonic_entropy.indices(), ", "), indices_str);
        let mnemonic_str = mnemonic_str
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(mnemonic_entropy.to_string(), mnemonic_str);
    }
}
