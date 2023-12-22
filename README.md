## Delve into low-level RISC Zero machines

<img src="title.png" align="right" alt="two dinosaurs playing stones that are flying" width="300"/>

Apart from the RISC-V virtual machine, RISC Zero also has a [non-erasing Turing machine](https://link.springer.com/chapter/10.1007/3-540-59175-3_104) used for recursion (including 
continuation). This is a very restricted machine, as follows.

- **No program counter (PC).** The program can only move in one single direction. As a result, there is no 
function call, no conditional branches, and no loop.
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
Like a regular (de)compiler, a number of optimization passes are then performed over the raw codes and try to simplify 
its logic by using function calls.

Note that our decompiler is not a new invention, as [preflight.rs](https://github.com/risc0/risc0/blob/main/risc0/zkvm/src/host/recursion/prove/preflight.rs) already comes with a tracing system, and [step_exec.cpp](https://github.com/risc0/risc0/blob/main/risc0/circuit/recursion-sys/cxx/step_exec.cpp) has left comments that explain the behavior of the instructions.

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
wom_init();
iop = read_iop(IOP_Header { count: 8, k_and_flip_flag: 2});
iop.write(m[1..=8]);
m[147] = iop.pop();
m[147] = m[147] * 268435454;
m[147] = m[147] - 14;
assert_eq!(m[147], 0);
poseidon.add_consts = 0; poseidon.state0 = to_montgomery!(m[388].0, m[389].0, m[390].0, m[391].0, m[392].0, m[393].0, m[394].0, m[395].0);
poseidon.add_consts = 1; poseidon.state1 += to_montgomery!(m[396].0, m[397].0, m[398].0, m[399].0, m[400].0, m[401].0, m[402].0, m[403].0);
poseidon.permute_and_store_state0_montgomery(&mut m[404..=411]);
sha_init();
sha_load(24864 + 43029 << 16);
sha_load(8263 + 2172 << 16);
sha_load(57490 + 21696 << 16);
sha_load(9586 + 12767 << 16);
sha_load(10960 + 61078 << 16);
sha_load(38323 + 3175 << 16);
sha_load(4401 + 65325 << 16);
sha_load(46224 + 54817 << 16);
sha_load(m[45].0 + m[45].1 << 16);
sha_load(m[49].0 + m[49].1 << 16);
sha_load(m[53].0 + m[53].1 << 16);
sha_load(m[57].0 + m[57].1 << 16);
sha_load(m[61].0 + m[61].1 << 16);
sha_load(m[65].0 + m[65].1 << 16);
sha_load(m[69].0 + m[69].1 << 16);
sha_load(m[73].0 + m[73].1 << 16);
for _ in 0..48 { sha_mix(); }
sha_fini(&mut m[115682..=115689]);
set_global(m[115733], 2);
set_global(m[115737], 3);
set_global(m[1], 0);
set_global(m[5], 1);
wom_fini();
```

### Instruction set

There is no documentation on this low-level machine, but the pre-flight program gives us a list.
```
BIT_AND_ELEM, BIT_OP_SHORTS, SHA_INIT, SHA_LOAD, SHA_MIX, SHA_FINI, WOM_INIT, WOM_FINI, 
SET_GLOBAL, CONST, ADD, SUB, MUL, INV, EQ, READ_IOP_HEADER, READ_IOP_BODY, MIX_RNG, 
SELECT, EXTRACT, POSEIDON_LOAD, POSEIDON_FULL, POSEIDON_PARTIAL, POSEIDON_STORE
```

One can refer to the [decompile.rs](src/bin/decompile.rs) for the detailed behavior of these functions.

### Decompilation passes

This repo implements a few passes that simplify the code.
- **ConstPass**: [const_pass.rs](src/pass/const_pass.rs). This pass replaces all the references to constants to the
constants themselves, removes the variables that are used to temporarily host the constants, and removes the indirection 
for extracting Fp from Fp4. 
- **MergeIOPPass**: [merge_iop_pass.rs](src/pass/merge_iop_pass.rs). This pass merges continuous IOP read requests into
a single line for human readability.
- **LiveVariableAnalysisPass**: [live_variable_analysis.rs](src/pass/live_variable_analysis.rs). This pass analyzes the 
lifetime of variables and tries to reuse the variable space. This lifts the restriction of write-once, in an aim to 
simplify the code for human readability. This pass may affect the structure of the code and should be used after other 
merging passes.
- **PoseidonPass**: [poseidon_pass.rs](src/pass/poseidon_pass.rs). This pass merges the Poseidon full and partial round 
calls into a single line for human readability.
- **ShaPass**: [sha_pass.rs](src/pass/sha_pass.rs). This pass merges the SHA-256 Init, Mix, Fini lines into a single line 
for human readability.
- **ReorderPass**: [reorder_pass.rs](src/pass/reorder_pass.rs). Since ConstPass and LiveVariableAnalysisPass may remove 
variables, the memory would have a lot of gaps in the middle. This pass removes such gaps by putting the remaining 
variables close to each other.

### Why is it important?

As we can see, the low-level machine has been used to implement recursion for existing RISC Zero programs. 
One who wants to implement variants of RISC Zero (such as, incorporating GKR proofs) will be able to "join" their version into
the official RISC Zero version, through the use of assumptions and resolution of them. 

Separately, as shown in the example of [Polygon Miden VM](https://0xpolygonmiden.github.io/miden-vm/design/main.html), the industry is indeed seeking for a very low-level 
virtual machine that can handle special demands, often inherent to building low-level zero-knowledge proof systems. For 
example, as one can see, this low-level machine is a Poseidon hash function resolver. 

### Credits and License
Most of the code are rephrased from RISC Zero (https://www.github.com/risc0/risc0).

One can refer to [LICENSE](LICENSE) for the information about licensing.
