<h1 align="center">steamstub_unpack</h1>

# System dependencies

| dependency |   arch   |     fedora     | debian / ubuntu |
|------------|----------|----------------|-----------------|
|  Crypto++  | crypto++ | cryptopp-devel | libcrypto++-dev |


# Building

```bash
git clone 'https://github.com/illnyang/steamstub_unpack.git'
cd steamstub_unpack
mkdir build && cd build
cmake ..
make
```

Protip: use WSL if you're using Windows.

# Example of usage

```console
# steamstub_unpack -i packed.exe -o unpacked.exe
```

# Supported variants
- 3.x (x86/x64)

Feel free to send me samples packed with other SteamStub variants @ issue tracker

# Credits
[atom0s/Steamless](https://github.com/atom0s/Steamless/) - steamstub_header struct & flags

----

<p align="center">shout-outs to da rin elites across the worldwide sea</p>
