## Delve into low-level RISC Zero machines

<img src="title.png" align="right" alt="two dinosaurs playing stones that are flying" width="300"/>

Apart from the RISC-V virtual machine, RISC Zero also has a non-erasing Turing machine used for recursion (including 
continuation). This is a very restricted machine, as follows.

- **No program counter (PC).** The program can only move in one single direction. As a result, there is no 
function call.
- **Non-erasing.** One cannot write to the same memory location twice (i.e., write-once).
- **Preprocessing.** The code is not part of the data, but hardcoded into the machine.

However, this machine is probably the most low-level machine so far in ZK, in that it provides direct access to virtually 
all the arithmetization interfaces.

- **Prime field.** The machine operates directly on the modulus of `pow(2,27) * 15 + 1`. This is unlike RISC Zero that 
is u32 native. This is somewhat similar to [Polygon Miden VM](https://0xpolygonmiden.github.io/miden-vm/design/main.html), which exposes an interface of modulus `pow(2,64) - pow(2,32) + 1`.
- **Field extension.** The memory is a degree-4 extension of the prime field, Fp4, under that modulus, and there are instructions 
to directly add, subtract, multiply, invert Fp4 elements. This opens a design space that does not exist before, as previous 
abstractions rarely expose the field extension.
- **Poseidon instructions.** The machine has specifically been optimized for [Poseidon hash functions](https://www.poseidon-hash.info/). This is used 
for opening the Merkle trees in FRI.

It appears that there is no domain-specific language for writing code for this low-level machine right now, as it 
seems that even RISC Zero is writing code in an almost manual manner. This repo is not intended to provide a writing 
framework at this moment, as we don't know enough about this low-level machine.

Instead, this repo provides two tools that help us delve into this low-level RISC Zero machine that did not receive 
sufficient attention.
- **Unzip.** An unzip tool, rephrased from [risc0/risc0/circuit/recursion/src/zkr.rs](https://github.com/risc0/risc0/blob/main/risc0/circuit/recursion/src/zkr.rs), 
which opens the `recursion_zkr.zip` in the RISC Zero GitHub repo, which is a Zip file under Zstd compression algorithm.
- **Decompile.** A decompiler, rephrased from [risc0/risc0/zkvm/src/host/recursion/prove/preflight.rs](https://github.com/risc0/risc0/blob/main/risc0/zkvm/src/host/recursion/prove/preflight.rs), 
which decompiles the `.zkr` file into a more human-readable format, at the same time trying to retain a Rust feeling.

### Decompile RISC Zero recursion circuits

One can download the `recursion_zkr.zip` from RISC Zero.
```console
wget https://github.com/risc0/risc0/raw/main/risc0/circuit/recursion/src/recursion_zkr.zip
```

Then, use the `unzip` tool to obtain the `.zkr` files.
```console
cargo run --bin unzip -- --file recursion_zkr.zip
```

This should give a few files:
- `identity.zkr`
- `join.zkr`
- `resolver.zkr`
- `test_recursion_circuit.zkr`
- `lift_14.zkr`, `lift_15.zkr`, ..., `lift_24.zkr`

Then, one can use the `decompile` tool to obtain `.ll0` files that contain a more human-readable format. We use the 
file extension `.ll0` to mean low-level RISC-Zero, since it is not RISC-V and not anything else.

```console
cargo run --bin decompile -- --file join.zkr
```

### Snapshot

Below is an extract from `join.ll0` that can give people a feeling about what the low-level code can do.

```rust
wom_init()
m[1] = (0, 1, 0, 0)
m[2] = m[1] * m[1]
m[152] = m[151] + m[150]
assert_eq!(m[2531], m[0])
iop = read_iop(IOP_Header { count: 256, k_and_flip_flag: 2})
m[2789] = iop.pop()
poseidon.write_state0_montgomery(&mut m[2823..2831])
poseidon.settings = PoseidonSettings { add_consts: 0 }
poseidon.state0 = to_montgomery!(m[2694].0, m[2695].0, m[2696].0, m[2697].0, m[2698].0, m[2699].0, m[2700].0, m[2701].0)
poseidon.settings = PoseidonSettings { add_consts: 1 }
poseidon.state1 += to_montgomery!(m[2702].0, m[2703].0, m[2704].0, m[2705].0, m[2706].0, m[2707].0, m[2708].0, m[2709].0)
poseidon.full()
poseidon.full()
poseidon.partial()
poseidon.full()
poseidon.full()
m[368206] = m[368189 + 9 * m[366371].0]
sha_init()
sha_load(m[281460].0 + m[281460].1 << 16)
sha_mix()
sha_fini(&mut m[560697..560705])
set_global(m[560697], 2)
set_global(m[560701], 3)
set_global(m[2487], 0)
set_global(m[2491], 1)
wom_fini()
```

### Instruction set

There is no documentation on this low-level machine, but the pre-flight program gives us a list.
```
BIT_AND_ELEM, BIT_OP_SHORTS, SHA_INIT, SHA_LOAD, SHA_MIX, SHA_FINI, WOM_INIT, WOM_FINI, 
SET_GLOBAL, CONST, ADD, SUB, MUL, INV, EQ, READ_IOP_HEADER, READ_IOP_BODY, MIX_RNG, 
SELECT, EXTRACT, POSEIDON_LOAD, POSEIDON_FULL, POSEIDON_PARTIAL, POSEIDON_STORE
```

One can refer to the [decompiler.rs](src/bin/decompile.rs) for the detailed behavior of these functions.

### Why is it important?

As we can see, the low-level machine has been used to implement recursion for existing RISC Zero programs. 
One who wants to implement variants of RISC Zero (such as, incorporating GKR proofs) will be able to "join" their version into
the official RISC Zero version, through the use of assumptions and resolution of them. 

Separately, as shown in the example of [Polygon Miden VM](https://0xpolygonmiden.github.io/miden-vm/design/main.html),, the industry is indeed seeking for a very low-level 
virtual machine that can handle special demands, often inherent to building low-level zero-knowledge proof systems. For 
example, as one can see, this low-level machine is a Poseidon hash function resolver. 

### Credits and License
Most of the code are rephrased from RISC Zero (https://www.github.com/risc0/risc0).

One can refer to [LICENSE](LICENSE) for the information about licensing.