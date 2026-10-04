# Tamarin models

`hybrid_tls13.spthy` is a **skeleton**, and its status is the first thing in its own header:
it has never been parsed by Tamarin, because the machine this project was built on has no
Haskell toolchain and Tamarin publishes no Windows binary.

It is here to save the modelling work, not to be run as-is. Read the header's three
"DECIDED / NOT DECIDED" notes before editing — in particular the undecided one, which is
**how to represent a KEM in Tamarin**. The common `aenc` shortcut models public-key
encryption, in which the adversary chooses the shared secret; that is sound for some
properties and unsound for others, and the choice has to be made deliberately rather than
inherited.

The claim to prove is not "the flight is authenticated" but "the flight is authenticated
**while at least one of the two signature keys is uncompromised**" — that is what makes the
construction hybrid. The file lists the lemmas, including the two controls that must
SUCCEED (Tamarin must find the attack) before any of the others mean anything.

See `docs/HANDOVER.md` for the full brief to whoever runs this.
