# evmelf
Small utility to translate ELF-format EVM binaries generated by [evm-llvm](https://github.com/etclabscore/evm_llvm).

It is intended to mimic Solidity's combined-json output format, used by various DAPP dev toolchains.

It currently only supports the equivalent of solc's `bin` option, but will be extended as evm-llvm provides more support.

# Usage
Use evmelf by calling it on one or more ELF binaries:
```
evmelf file1.elf file2.elf file3.elf
```
Enable pretty-printed JSON output using the `--pretty-json` flag, much like one would using solc.

More info can be found by invoking:
```
evmelf --help
```
# Authors
Jake Lang
