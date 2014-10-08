# [libhashsig](https://github.com/ps-auxw/libhashsig)

libhashsig is a stand-alone library for the creation and verification of
digital signatures based on a hash based signature scheme.

It is implemented employing Lamport, Diffie, Winternitz, Merkle one-time
signatures, as described in
[draft-mcgrew-hash-sigs-02](http://tools.ietf.org/html/draft-mcgrew-hash-sigs-02),
combined with the lazy Merkle forest approach described by [Adam
Langley](https://www.imperialviolet.org/2013/07/18/hashsig.html) to allow for a
practically unlimited number of signatures.

libhashsig is very new code and has not been reviewed by, well, pretty much
anybody so far. Please do not use it for anything important.

In the second section of this document, the motivation for writing libhashsig
are shortly explained. Following that, in section three various design
considerations are explained. The fourth section presents various cryptographic
considerations. In section five, some rough numbers about performance are
given. Section six provides installation instructions. The seventh section
mentions where to find detailled usage information. Finally, section eight
gives contact information for the author and acknowledgements.

## Motivation

I have written libhashsig because it seemed like an interesting project. From
what I could see, there was no available, working code for hash based signature
systems that provides similar features, such as a practically unlimited number
of one-time signature keys, when I was writing this code.

Two key features of hash based signature schemes are:

* Resistance against quantum computers.
* Relatively simple. No bignums required.

## Design considerations

Keccak has been chosen as the underlying hash function, because its internal
state is big enough to avoid running into the pigeonhole principle when
generating the leaves of the lazily calculated Merkle forest. (For example, an
algorithm with 512 bits of state would have been insufficient by a small
degree.)

During normal operation (i.e. unless killed during processing), libhashsig will
try not to leave private data in memory. Private data in buffers is processed
in-place into public keys and signatures or overwritten by other subsequent
working steps.

The library does not copy the private key from the user supplied buffer. It is
the user's responsibility to take care not to change or free the private key
buffer until the corresponding hashsig context is destroyed and zero the buffer
in a secure manner, once no longer needed.

Following a "do one thing and do it well" philosophy, libhashsig does not
include facilities for securely zeroing memory or retrieving entropy, as both
of these things are hard to do both right and in a portable way. The user is
advised to look at other libraries (e.g. libsodium) for these purposes.

The libhashsig code has been written in a flexible way, which allows swapping
out the hash function or modifying various parameters of the signature systems
quite easily at compile time. With a little bit of effort, parameter choice can
be made runtime configurable. I will likely do this at some later point.
However, the impact of such a modification on performance remains to be seen.

After key generation, no source of entropy is required to generate or verify
signatures. This way, a [certain
class](http://www.eurogamer.net/articles/2011-01-08-deep-insecurity-article) of
failure modes can be avoided.

## Security

In this section, an attempt is made at describe attacks (and possibly
countermeasures) against the specific way libhashsig generates and verifies
hash based digital signatures.

libhashsig uses Keccak with 256 bit hashes, which provide collision resistance
of 2^128, preimage resistance of 2^256 and quantum preimage resistance of
2^128. The capacity parameter is chosen high enough to support these numbers.

### Attacking key choice

The specific key pair libhashsig uses for signing a message depends on the
message hash. This can lead to the following attack scenarios:

#### Scenario 1

An attacker can find a collision in the hash function. If the attacker can make
a victim sign one of the messages, the attacker can substitute the other
message and the signature will verify.

#### Scenario 2

An attacker can find one or more collisions in the hash function. If the
attacker can make the victim sign two or more of these colliding messages,
reuse of the one-time signature key occurs. This may allow an attacker to sign
arbitrary messages using that leaf key.

However, due to the fact that leaf keys are selected by the message hash, an
attacker will be unable to make use of the compromised leaf key to sign
messages that do not hash to the same hash value to begin with, which makes
this scenario basically equivalent to scenario 1.

#### Mitigation

If these attacks are of concern in the context of a given use case, they can be
mitigated (with high probability), by attaching a random nonce to every signed
message.

The complexity of these attacks can also be increased by increasing the message
hash size and either increasing the number of levels in the individual Merkle
trees or by adding further layers of trees.

Please note that an attacker will have to find new collisions for each public
key the attacker wishes to attack. This is due to the fact that libhashsig
personalizes the message hash with the public key that signs the message.

### Attacking the public key

An attacker with the ability to find preimages for the hash function, can
attempt to build up the top level Merkle tree backwards to generate their own
private key matching the public key.

With default settings, 2^9-2 preimages with a specific length (2 * hash length)
need to be found. If configured for Merkle trees with a height of 16, this
number rises to 2^17-2 preimages of the same form.

Again, this attack can be made more difficult by increasing the length of the
hash. If Keccak is broken, it can also be swapped out quite easily, as long as
care is taken that the new hash function has sufficiently big internal state.

### Attacking Merkle tree leaves

Each leaf in the Merkle trees built by libhashsig corresponds to an LDWM
one-time signature public key. A promising approach for an attacker with the
ability to find preimages in the hash function, would be to attack a public key
or LDWM signature of one of or more of the leaves of the top-most Merkle tree.
If the attacker manages to find private keys corresponding to all public key
leaves of the top-most Merkle tree, the attacker can sign completely arbitrary
messages. If an attacker compromises a single leaf, the attacker will probably
still be able to sign nearly arbitrary messages by applying a brute force
search on some unimportant data inside the message, to find one, that matches
the given leaf.

By default, each of the Merkle trees has 2^8 leaves. This value can be easily
tweaked to allow Merkle trees with 2^16 leaves. However, this increase results
in significantly higher signature generation time, while only slightly
impacting the amount of time an attacker has spend to find a compatible
message, if the attacker has already compromised a single leaf.

Attacking the leafs of Merkle trees further down the path would quickly
increase the time an attacker would have to spend on searching for compatible
messages. Therefore, it seems unlikely that an attacker will attack leaves on
the lower levels. Concentrating on the root tree will give the best results,
unless an attacker can significantly speed up their attack by attacking more
hashes at the same time.

Since libhashsig keys the hash function used for one time signature generation
with the position of the current Merkle tree within the forest, it seems
unlikely that such a speed-up exists in this case.

If such an attack seems troublesome, it may be worth considering an increas in
hash size for the upper Merkle trees to discourage an attacker from choosing
this path of attack. However, it seems rather questionable whether this would
provide any significant benefit.

### Timing attacks

While the generation and verification of signatures generated by libhashsig is
not constant time, neither depends on any secret data. Therefore, timing
attacks should not be possible.

(This applies to the one-time signature and lazy Merkle forest parts of the
system. Keccak should be constant time. If it is not, that needs to be fixed.)

### Conclusions

It appears that attacks for which it is sufficient that an attacker can find
collisions in the hash function used by libhashsig can be mitigated easily
enough.

At the same time, the given resistance level against quantum preimage attacks
of 2^128 seems quite sufficient against even well funded adversaries. If, for
some reason or other, it is still deemed insufficient, the hash function size
can be easily doubled to provide a 2^256 resistance level. This will, however,
significantly increase both signature size and the time required to sign and
verify messages.

Of course, this sections only includes attacks which I could come up with or
know about myself. Corrections and additions are welcome.

## Performance

Signatures have a length of 77,825 Bytes. Both private and public key have a
length of 256 bits with an additional a one byte header.

Generating one signature on my Sandy Bridge i5 running at 2.53GHz takes about
7 seconds, when compiled with gcc-4.7.2 against glibc. Verfication of
signatures is much faster at about 0.01 seconds.

As can be seen, it's probably not a good idea to use libhashsig for things
requiring high/interactive performance or quickly signing and transmitting
messages. Instead, it is aimed at providing secure signatures that can be used
to verify other, shorter lived signing keys, software packages and similar
applications were few and bigger messages are signed.

The current parameters used by libhashsig have been chosen as a reasonable
trade-off between signature size and signature generation time.

## Installation

To install:

```
  mkdir build
  cd build
  cmake ..
  make && su -c "make install"
```

To install with a different prefix change the `cmake` line as follows:

```
  cmake -DCMAKE_INSTALL_PREFIX:PATH=/path/to/prefix ..
```

To debug the build process, you can modify the `make line as follows:

```
  make VERBOSE=1
```

You will find some test programs in the `bin/` folder within your build folder.

Once again: Please do not use libhashsig for anything important. The code needs
some reviewing. Rather than using it to secure your launch codes (DON'T!),
please read through it, play around with it, write tests, etc. and see if you
can find any issues. If so, please let me know so that I can fix them. Thanks!

Of course, if you do review the code but don't find any issues, I'd also
appreciate you letting me know.

### Portability

While the code should be portable, it has yet to be tested on anything but
linux on amd64 with gcc and clang.


## Documentation

See: `man 3 libhashsig`

## Authors

libhashsig has been written by ps-auxw.

PGP key id: `4D7B5A80`

Fingerprint: `BEFF BEF4 026A 92B9 C299  AA03 DCE4 1D82 4D7B 5A80`

Keccak was implemented by the Keccak, Keyak and Ketje Teams.
