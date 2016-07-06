
asm2plan9s
==========

Tool to generate BYTE sequences for Go assembly as generated by YASM.

Installation
------------

Make sure YASM is installed on your platform. Get the code and compile with `go install`.

Example
-------

```
$ more example.s
                                 // VPADDQ  XMM0,XMM1,XMM8
$ asm2plan9s example.s
$ echo example.s
    LONG $0xd471c1c4; BYTE $0xc0 // VPADDQ  XMM0,XMM1,XMM8
```

The instruction to be assembled needs to start with a `//` preceded by either a single space 
The preceding characters will be overwitten by the correct sequence (irrespective of its contents) so when changing the instruction, rerunning `asm2plan9s` will update the BYTE sequence generated.

Starting position of instruction
--------------------------------

The starting position of the `//` comment needs to follow the (imaginary) sequence with either a single space or a space followed by a back slash plus another space (see support for defines below).
Upon first entering an instruction you can type eg `LONG $0x00000000 // VZEROUPPER` to trigger the assembler. 

Support for defines
-------------------

If you are using #define for 'macros' with the back-slash delimiter to continue on the next line, this will be preserved.

For instance:
```
                                 \ // VPADDQ  XMM0,XMM1,XMM8
```

will be assembled into

```
    LONG $0xd471c1c4; BYTE $0xc0 \ // VPADDQ  XMM0,XMM1,XMM8
```

Extensive example
-----------------

For a more extensive example see [compressAvx_amd64.s](https://github.com/minio/blake2b-simd/blob/master/compressAvx_amd64.s)
