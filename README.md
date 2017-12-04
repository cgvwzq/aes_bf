# aes_bf
Script for finding plaintexts with certain features producing AES ciphertexts with more certain features...

```
$ make
$ ./aes-brute-force                                                                                                                                                      [12:09:04]
[+] INFO: 1 concurrent threads supported in hardware.

[+] Search parameters:

        - n_threads:    1
        - payload:      4D346731_435F6330_306B3133_5F465457
        - key:          FD621FE5_A2B40253_9DFA147C_A9272778
        - iv:           20202020_20202020_20202020_20202020
        - plain_mask:   A0A0A0A0_A0A0A0A0_A0A0A0A0_A0A0A0A0
        - plain:        20202020_20202020_20202020_20202020
        - cipher:       3EA77555_C763A583_2206A296_B3D220D4
        - next_block:   7AE33111_8327E1C7_6642E6D2_F7966490

[+] Dividing work in jobs...

        thread_0: 0 jobs (mask : FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)

        launching 112 bits search

[+] Thread 0 claims to have found a valid ciphertext
[+] CIPHER FOUND: 458D4856_C763A583_2206A296_B3D220D4

[+] Performances:
        9324676 AES128 operations done in 0.49919s
        53 ns per AES128 operation
        18.68 million ciphers per second
[+] Ciphertext: 458D4856_C763A583_2206A296_B3D220D4
[+] Plaintext: 406C3E5D_7254745D_5D2F724D_3E7D762C
        ascii: @l>]rTt]]/rM>}v, (length=16)
[+] Next block: 7AE33111_8327E1C7_6642E6D2_F7966490
[+] Next block XOR cipher: 3F6E7947_44444444_44444444_44444444
        ascii: ?nyGDDDDDDDDDDDD (length=16)
```

Edit `src/aes-brute-force.cpp` and uncomment `#DEFINE PADDING 1` for bf last block:

```
$ make
$ ./aes-brute-force                                                                                                                                                      [12:11:20]
[+] INFO: 1 concurrent threads supported in hardware.

[+] Search parameters:

        - n_threads:    1
        - payload:      4D346731_435F6330_306B3133_5F465457
        - key:          FD621FE5_A2B40253_9DFA147C_A9272778
        - iv:           4D346731_435F6330_306B3133_5F465457
        - plain_mask:   A0A0A0A0_A0A0A0A0_A0A0A0A0_A0A0A0A0
        - plain:        20202020_20202020_20202020_20202001
        - cipher:       00000000_00000000_00000000_00000000
        - next_block:   00000000_00000000_00000000_00000000

[+] Dividing work in jobs...

        thread_0: 0 jobs (mask : FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF)

        launching 112 bits search
        (debug): 35564375_37000000_00000000_00000000
        (debug): 397C5B75_43000000_00000000_00000000
l       (debug): 3F587475_4D000000_00000000_00000000
        (debug): 437E4276_57000000_00000000_00000000

[+] Thread 0 claims to have found a valid ciphertext
[+] CIPHER FOUND: 45664F67_58000000_00000000_00000000

[+] Performances:
        1223977628 AES128 operations done in 72.9225s
        59 ns per AES128 operation
        16.78 million ciphers per second
[+] Ciphertext: 45664F67_58000000_00000000_00000000
[+] Plaintext: 78542548_5B24392A_4E326628_76465401
        ascii: xT%H[$9*N2f(vFT (length=16)
```

The plaintext producing a ciphertext with our desired payload "M4g1C_c00k13_FTW" is:

`@l>]rTt]]/rM>}v,?nyGDDDDDDDDDDDDxT%H[$9*N2f(vFT`
