# Roppy

Roppy is an home-made script based on the python bindings ([pydis](https://github.com/novogen/pydis)) of the [zydis disassembler](https://github.com/zyantific/zydis).

### Warnings

**ONLY TESTED ON x64 ARCH FOR NOW**

**IN DEVELOPMENT**

## Why ?

- It's fun.
- It's a good way to learn.
- I wasn't completely satisfied of the results of the well-known tools.


## How to use it ?

Easy as pie!


```
pip install -r requirements.txt
```

```
usage: main.py [-h] [-m MNEMONIC] [-r REGISTER] [-l MAX_LEN]
               [-b BYTES_BACKWARD] [-s] [-f]
               file

Look for interesting gadgets inside a binary.

positional arguments:
  file                  The binary file to inspect

optional arguments:
  -h, --help            show this help message and exit
  -m MNEMONIC, --mnemonic MNEMONIC
                        Search for a specific mnemonic
  -r REGISTER, --register REGISTER
                        What register you want to manipulate.
  -l MAX_LEN, --max-len MAX_LEN
                        Maximum lenght of gadgets found. (default to 8)
  -b BYTES_BACKWARD, --bytes-backward BYTES_BACKWARD
                        Number of bytes to browse backwards each time a ret
                        instruction if found. (default to 30)
  -s, --symbols         Try to resolve symbols (prototypal only .symtab for
                        now).
  -f, --follow          Immediately prints gadgets at finding. Useful for
                        reeeally big binaries.
```


If you find any bugs, don't hesitate to open a ticket ;-)


