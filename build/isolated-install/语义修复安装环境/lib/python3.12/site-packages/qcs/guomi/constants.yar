// Guomi standard constants reviewed from team extensions and MIT CryptoScan
// scan configurations. Matches are clues only; no implementation assignment.
rule guomi_sm3_iv {
  meta: algorithm = "SM3"
  strings:
    $be = { 73 80 16 6F 49 14 B2 B9 17 24 42 D7 DA 8A 06 00 A9 6F 30 BC 16 31 38 AA E3 8D EE 4D B0 FB 0E 4E }
    $le = { 6F 16 80 73 B9 B2 14 49 D7 42 24 17 00 06 8A DA BC 30 6F A9 AA 38 31 16 4D EE 8D E3 4E 0E FB B0 }
  condition: any of them
}
rule guomi_sm4_tables {
  meta: algorithm = "SM4"
  strings:
    $sbox = { D6 90 E9 FE CC E1 3D B7 16 B6 14 C2 28 FB 2C 05 2B 67 9A 76 2A BE 04 C3 AA 44 13 26 49 86 06 99 }
    $fk_be = { A3 B1 BA C6 56 AA 33 50 67 7D 91 97 B2 70 22 DC }
    $fk_le = { C6 BA B1 A3 50 33 AA 56 97 91 7D 67 DC 22 70 B2 }
    $ck_be = { 00 07 0E 15 1C 23 2A 31 38 3F 46 4D 54 5B 62 69 }
    $ck_le = { 15 0E 07 00 31 2A 23 1C 4D 46 3F 38 69 62 5B 54 }
  condition: any of them
}
rule guomi_sm2_curve {
  meta: algorithm = "SM2"
  strings:
    $b = { 28 E9 FA 9E 9D 9F 5E 34 4D 5A 9E 4B CF 65 09 A7 F3 97 89 F5 15 AB 8F 92 DD BC BD 41 4D 94 0E 93 }
    $g = { 32 C4 AE 2C 1F 19 81 19 5F 99 04 46 6A 39 C9 94 8F E3 0B BF F2 66 0B E1 71 5A 45 89 33 4C 74 C7 }
  condition: any of them
}
