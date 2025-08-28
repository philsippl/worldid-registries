// SPDX-License-Identifier: MIT

pragma solidity >=0.8.8;

library Poseidon2T2 {
    // BN256 scalar field
    uint256 constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 constant rounds_f = 8;
    uint256 constant rounds_p = 56;

    function compress(uint256[2] memory inputs) public pure returns (uint256) {
        bytes memory ext = ext_constants;
        bytes memory intrc = int_constants;
        assembly {
            let F := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

            // Load inputs
            let l := mload(add(inputs, 0x20))
            let r := mload(add(inputs, 0x40))

            // Initial linear layer: [1 1; 1 1]
            let sum := add(l, r)
            l := add(l, sum)
            r := add(r, sum)

            // Pointers to constants in memory (length-prefixed)
            let EXT := add(ext, 0x20)
            let INT := add(intrc, 0x20)

            // First 4 external rounds
            {
                let i := 0
                for {} lt(i, 4) { i := add(i, 1) } {
                    // add external round constants
                    l := add(l, mload(add(EXT, mul(i, 0x40))))
                    r := add(r, mload(add(add(EXT, mul(i, 0x40)), 0x20)))
                    // sbox on both
                    let t := mulmod(l, l, F)
                    l := mulmod(mulmod(t, t, F), l, F)
                    t := mulmod(r, r, F)
                    r := mulmod(mulmod(t, t, F), r, F)
                    // external matrix multiplication
                    let s := add(l, r)
                    l := add(l, s)
                    r := add(r, s)
                }
            }

            // 56 internal rounds
            {
                let j := 0
                for {} lt(j, 56) { j := add(j, 1) } {
                    // add internal constant to l
                    l := add(l, mload(add(INT, mul(j, 0x20))))
                    // sbox on l only
                    let t := mulmod(l, l, F)
                    l := mulmod(mulmod(t, t, F), l, F)
                    // reduce r to keep bounded
                    r := mod(r, F)
                    // internal matrix multiplication
                    let s := add(l, r)
                    l := add(l, s)
                    r := add(add(r, r), s)
                }
            }

            // Remaining 4 external rounds
            {
                let k := 4
                for {} lt(k, 8) { k := add(k, 1) } {
                    // add external round constants
                    l := add(l, mload(add(EXT, mul(k, 0x40))))
                    r := add(r, mload(add(add(EXT, mul(k, 0x40)), 0x20)))
                    // sbox on both
                    let t := mulmod(l, l, F)
                    l := mulmod(mulmod(t, t, F), l, F)
                    t := mulmod(r, r, F)
                    r := mulmod(mulmod(t, t, F), r, F)
                    // external matrix multiplication
                    let s := add(l, r)
                    l := add(l, s)
                    r := add(r, s)
                }
            }

            // Add first input and reduce
            l := add(l, mload(add(inputs, 0x20)))
            mstore(0x00, mod(l, F))
            return(0x00, 0x20)
        }
    }

    // Embed constants into code for cheap codecopy access
    bytes constant ext_constants =
        hex"09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a70c0356530896eec42a97ed937f3135cfc5142b3ae405b8343c1d83ffa604cb811e28a1d935698ad1142e51182bb54cf4a00ea5aabd6268bd317ea977cc154a3027af2d831a9d2748080965db30e298e40e5757c3e008db964cf9e2b12b91251f1e6f11ce60fc8f513a6a3cfe16ae175a41291462f214cd0879aaf43545b74e032a67384d3bbd5e438541819cb681f0be04462ed14c3613d8f719206268d142d30b66fdf356093a611609f8e12fbfecf0b985e381f025188936408f5d5c9f45d0012ee3ec1e78d470830c61093c2ade370b26c83cc5cebeeddaa6852dbdb09e2119b9b63d2f108e17e63817863a8f6c288d7ad29916d98cb1072e4e7b7d52b376015bee1357e3c015b5bda237668522f613d1c88726b5ec4224a20128481b4f7f2953736e94bb6b9f1b9707a4f1615e4efe1e1ce4bab218cbea92c785b128ffd10b069353ba091618862f806180c0385f851b98d372b45f544ce7266ed6608dfc304f74d461ccc13115e4e0bcfb93817e55aeb7eb9306b64e4f588ac97d81f42915bbf146ce9bca09e8a33f5e77dfe4f5aad2a164a4617a4cb8ee5415cde913fc0ab4dfe0c2742cde44901031487964ed9b8f4b850405c10ca9ff23859572c8c60e32db320a044e3197f45f7649a19675ef5eedfea546dea9251de39f9639779a";

    bytes constant int_constants =
        hex"0252ba5f6760bfbdfd88f67f8175e3fd6cd1c431b099b6bb2d108e7b445bb1b9179474cceca5ff676c6bec3cef54296354391a8935ff71d6ef5aeaad7ca932f12c24261379a51bfa9228ff4a503fd4ed9c1f974a264969b37e1a2589bbed2b911cc1d7b62692e63eac2f288bd0695b43c2f63f5001fc0fc553e66c0551801b05255059301aada98bb2ed55f852979e9600784dbf17fbacd05d9eff5fd9c91b5628437be3ac1cb2e479e1f5c0eccd32b3aea24234970a8193b11c29ce7e59efd928216a442f2e1f711ca4fa6b53766eb118548da8fb4f78d4338762c37f5f20432c1f47cd17fa5adf1f39f4e7056dd03feee1efce03094581131f2377323482c907abad02b7a5ebc48632bcc9356ceb7dd9dafca276638a63646b8566a621afc90230264601ffdf29275b33ffaab51dfe9429f90880a69cd137da0c4d15f96c3c1bc973054e51d905a0f168656497ca40a864414557ee289e717e5d66899aa0a92e1c22f964435008206c3157e86341edd249aff5c2d8421f2a6b22288f0a67fc1224f38df67c5378121c1d5f461bbc509e8ea1598e46c9f7a70452bc2bba86b802e4e69d8ba59e519280b4bd9ed0068fd7bfe8cd9dfeda1969d2989186cde20e1f1eccc34aaba0137f5df81fc04ff3ee4f19ee364e653f076d47e9735d98018e1672ad3d709a353974266c3039a9a7311424448032cd1819eacb8a4d4284f582283e3fdc2c6e420c56f44af5192b4ae9cda6961f284d24991d2ed602df8c8fc71c2a3d120c550ecfd0db0957170fa013683751f8fdff59d6614fbd69ff394bcc216f84877aac6172f7897a7323456efe143a9a43773ea6f296cb6b8177653fbd2c0d272becf2a75764ba7e8e3e28d12bceaa47ea61ca59a411a1f51552f9478816e34299865c0e28484ee7a74c454e9f170a5480abe0508fcb4a6c3d89546f43175ceba599e96f5b375a232a6fb9cc71772047765802290f48cd939755488fc50c7594440dc48c16fead9e1758b028066aa410bfbc354f54d8c5ffbb44a1ee321a3c29bc39f21bb5c466db7d7eb6fd8f760e20013ccf912c92479882d919fd8d0ccfdd906f3426e5c0986ea049b253400855d349074f5a6695c8eeabcd22e68f14f6bc81d9f186f62bdb475ce6c9411866a7a8a3fd065b3ce0e699b67dd9e7960962b82789fb3d129702ca70b2f6c5aacc099810c9c495c888edeb7386b970521a880af7074d18b3bf20c79de25127bc13284ab01ef02575afef0c8f6a31a86d10cba18419a6a332cd5e77f0211c154b20af2924fc20ff3f4c3012bb7ae9311b057e62a9a8f89b3ebdc76ba63a9eaca8fa27b7319cae3406756a2849f302f10d287c971de91dc0abd44adf5384b4988cb961303bbf65cff5afa0413b44280cee21df3388af1687bbb3bca9da0cca908f1e562bc46d4aba4e6f7f7960e306891d1be5c887d25bce703e25cc974d0934cd789df8f70b498fd83eff8b560e1682b3268da36f76e568fb68117175cea2cd0dd2cb5d42fda5acea48d59c2706a0d5c10e17ab091f6eae50c609beaf5510ececc5d8bb74135ebd05bd06460cc26a5ed604d727e728ffa0a67aee535ab074a43091ef62d8cf83d270040f5caa1f62af400ddbd7bf9c29341581b549762bc022ed33702ac10f1bfd862b15417d7e39ca6e2790eb3351621752768162e82989c6c234f5b0d1d3af9b588a29c49c8789654b1e457c601a63b73e4471950193d8a570395f3d9ab8b2fd0984b764206142f9e921ae64301dca9625638d6ab2bbe7135ffa90ecd0c43ff91fc4c686fc46e091b00379f63c8ce3468d4da293166f494928854be9e3432e09555858534eed8d350b002d56420359d0266a744a080809e054ca0e4921a46686ac8c9f58a324c35049123158e5965b5d9b1d68b3cd32e10bbeda8d62459e21f4090fc2c5af963515a60be29fc40847a941661d14bbf6cbe0420fbb2b6f52836d4e60c80eb49cad9ec11ac96991dec2bb0557716142015a453c36db9d859cad5f9a233802f24fdf4c1a1596443f763dbcc25f4964fc61d23b3e5e12c9fa97f18a9251ca3355bcb0627e12e0bcd3654bdfa76b2861d4ec3aeae0f1857d9f17e715aed6d049eae3ba32120fc92b4f1bbea82b9ea73d4af9af2a50ceabac7f37154b1904e6c76c7cf964ba1f9c0b1610446442d6f2e592a8013f40b14f7c7722236f4f9c7e9652338727620ebd74244ae72675f8cde06157a782f4050d914da38b4c058d159f643dbbf4d32cb7f0ed39e16e9f69a9fafd4ab951c03b0671e97346ee397a839839dccfc6d11a9d6e2ecff022cc5605443ee41bab20ce761d0514ce526690c72bca7352d9bf2a115439607f335a5ea83c3bc44a9331d0c13326a9a7ba3087da182d648ec72f23f9b6529b5d040d15b8fa7aee3e3410e738b56305cd44f29535c115c5a4c06005872c16db0f72a2249ac6ba484bb9c3a3ce97c16d58b68b260eb939f0e6e8a71300bdee08bb7824ca20fb80118075f40219b6151d55b5c52b624a7cdeddf6a7";
}
