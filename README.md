## Runtime comparison of block cipher-based hash functions

This script is a practical part of a runtime comparison of block cipher-based hash functions.

### Idea

Acceleration of hash-based signature processes like XMSS through:

1. a fast hash function based on block cipher and
2. a correspondingly fast block cipher.

### Implementation

Hash function MDC-2 with AES as block cipher and hardware acceleration AES-NI in Python

### Result

1. Runtime comparison in milliseconds and clock cycles of the processor

|                   | milliseconds | clock cycles |
|:-----------------:|:------------:|:------------:|
| SHA-3 (256 bit)	  | 0,19097      |	512943      |
| MDC-2 with AES-NI |	0,13577      |	255849      |

2. Runtime comparison of key generation, signature and verification from 1024 bits to 256 bits in milliseconds

| XMSS with	        | key generation | signature | verification |
|:-----------------:|:--------------:|:---------:|:------------:|
| SHA-3 (256 bit)   | 13101,87879    | 12,60402	 | 14,51372     |
| MDC-2 with AES-NI	| 9314,77239	   | 8,96082	 | 10,31852     |

### License

This script is licensed under the MIT license. See [LICENSE-file](./LICENSE) for details.

### Copyright

Copyright (c) 2020 [Tim Kohlstadt](mailto:tim.kohlstadt@blun.org).
