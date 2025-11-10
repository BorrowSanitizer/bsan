# Summary
[summary]: #summary
We propose adding an unstable option that will lower MIR [`Retag`](https://doc.rust-lang.org/core/intrinsics/mir/fn.Retag.html) statements into function calls. This will support out-of-tree tools that use native instrumentation to find undefined behavior.

# Motivation
[motivation]: #motivation
Miri is the only tool that supports finding violations of Rust's latest aliasing models. However, it cannot find these types of undefined behavior if they are triggered by operations that span foreign function boundaries. This tooling gap has caused developers to miss bugs in high-profile crates. An earlier version of the crate [`flate2-rs`](https://github.com/rust-lang/flate2-rs/pull/394) (which is maintained by the Rust project) had an aliasing violation that was caused by passing a mutable borrow to the following foreign function:
```rust
let ret = mz_deflateInit2(&mut *state, ...)
```
The Rust compiler is allowed to assume that ownership of `state` will be returned to the caller. However, the C library broke this invariant by keeping a copy of this pointer.
```C
// The pointer `s` was derived from `&mut *state`.
strm->state = (struct internal_state FAR *)s;
```
Later on, `state` was mutated on the Rust side of the FFI boundary through a different mutable reference. This invalidated all pointers derived from other references to `state`—including the one that was copied by the C library. This made it undefined behavior to access this invalid pointer on the C side of the FFI boundary.

## Provenance
Miri detects aliasing errors by tracking the *provenance* of each pointer, which indicates "where and when" it is allowed to access memory (see RFC [#3559](https://rust-lang.github.io/rfcs/3559-rust-has-provenance.html)). Rust does not have a canonical provenance model yet. However, both the [Stacked Borrows](https://plv.mpi-sws.org/rustbelt/stacked-borrows/paper.pdf) and [Tree Borrows](https://iris-project.org/pdfs/2025-pldi-treeborrows.pdf) models have been proposed. Miri implements these models by associating each memory allocation with a unique "allocation ID" and a set of permissions. Permissions are stored within a stack or a tree, depending on which model is enabled. Each permission is labelled by a "borrow tag". Each pointer's [Provenance](https://github.com/rust-lang/miri/blob/7d5ae365eb1db28d15e540d43a50530a49512db4/src/machine.rs#L267) metadata includes the ID for an allocation and the borrow tag indicating the pointer's permission to access locations within that allocation. Before each memory access, Miri validates the pointer's provenance metadata to determine if that memory access is defined behavior.

A *retag* statement updates a pointer's borrow tag, assigning it a new permission within the stack or tree. The semantics and locations of retags vary under the each aliasing model, but the core mechanism remains the same; a new tag replaces the old one. However, only certain retags are present as explicit MIR statements. The rest are implicitly executed by Miri in the process of interpreting assignment statements. All explicit retags are discarded before MIR is lowered into Rust's codegen backends. This makes it impossible to develop tools that can track and update provenance metadata within lower-level representations of Rust programs.

To overcome Miri's lack of support for foreign function calls, developers will need tools that can track provenance in lower-level representations. We propose a implementing standardized interface that third-party tools can use control the location and semantics of retag statements through compiler plugins, as well as a mechanism for lowering retags deeper into Rust's codegen backends.

# Guide-level explanation
The precise semantics of Stacked and Tree Borrows are out of scope for this RFC. Instead, we want to describe retagging with just enough detail so that developers who are unfamiliar with Stacked and Tree Borrows models can reason about the implications of our proposal; and developers who *are* familiar with these models are confident that our lower-level retags are correct and precise enough to implement Miri's run-time instrumentation.

## Explicit Retags

Consider the following Rust program, which has undefined behavior under both of Rust's aliasing models.
```rust
fn example(x: Option<Box<i32>>) {
    if let Some(mut x) = x {
        // Get a pointer to the inside of the `Box`.
        let ptr_x: *mut i32 = &raw mut *x;
        // Turn it into a mutable borrow...
        let rx = &mut unsafe { *ptr_x };
        // ...but still keep using the pointer.
        let prev = unsafe { core::ptr::replace(ptr_x, T::default()) };
        // writing to the pointer invalidates the
        // "unique" mutable borrow, so this write access
        // is undefined behavior.
        *rx = prev;
    }
}
```
Miri compiles this example using the unstable flag `-Zmir-emit-retag`. In this mode, the compiler produces [`Retag`](https://doc.rust-lang.org/beta/nightly-rustc/rustc_middle/mir/enum.StatementKind.html) MIR statements.
```rust
pub enum StatementKind<'tcx> {
    ...
    Retag(RetagKind, Box<Place<'tcx>>),
    ...
}
```
We refer to these statements as "explicit retags". Note that retags apply to an entire `Place`, and a place may contain one or more references. Miri interprets a retag by recursively expanding it to apply to each of the references inside the target place.

There are multiple situations where explicit retags are emitted. Each situation corresponds to a variant of [`RetagKind`](https://doc.rust-lang.org/beta/nightly-rustc/rustc_middle/mir/enum.RetagKind.html).

Arguments that contain references are explicitly retagged in the entry-block of a function. The type `Option<&mut T>` contains a reference, so `x` needs a "function-entry" retag (`RetagKind::FnEntry`). When we compile this program with `-Zmir-emit-retag`, we see the following MIR for the function `example`:
```rust
fn example(_1: Option<Box<i32>>) -> () {
    ...
    bb0: {
        Retag([fn entry] _1);
```
If a place is assigned a value that contains a reference, then the place will be retagged immediately after the assignment. This is referred to as a "default" retag (`RetagKind::Default`) and it excludes borrowing (e.g. `let x = &mut y;`), which Miri handles implicitly. We need this kind of retag to handle true branch of the conditional in our example:
```rust
if let Some(mut x) = x {
```
The MIR for this fragment indicates that we are moving an `Option<Box<&mut T>>`, which contains a reference, so we need to retag the target of the assignment:
```
_2 = move ((_1 as Some).0: &mut i32);
Retag(_2);
```
Finally, certain assignment statements take the following form:
```
y = &raw mut *x;
y = &raw const *x;
```
If `x` is a `Box` that came from the global allocator, then we need to retag `y` after the assignment. This happens in our example when we assign to `ptr_x`:
```
let ptr_x: *mut i32 = &raw mut *x;
```
This statement compiles to the following MIR:
```
ptr_x = &raw mut (*x);
Retag([raw] ptr_x);
```

### Making the Implicit Explicit
Miri also implicitly applies a retag when it interprets certain assignment statements. One of these "implicit retags" occurs in our example:
```
let rx = &mut unsafe { *ptr_x };
```
When Miri interprets this statement, it will retag the pointer produced by evaluating the expression `&mut unsafe { *ptr_x }` on-the-fly; after it has been evaluated, but before it is assigned to the place `rx`.

We propose adding a configuration option that will make all retags explicit. We can see the effects of this by looking at the MIR for our reborrow again:
```
rx = &mut ptr_x;
```
For this MIR to be semantically equivalent to how it is interpreted by Miri, we will need to emit a retag for the expression before we assign it to `rx`. For that to happen, we need a temporary variable.
```
tmp = &mut ptr_x;
Retag(tmp)
rx = move (tmp)
```
Under the Stacked Borrows model, Miri will also implicitly retag raw pointers at the moment when they are cast from references. For example, the following statement would trigger two retags under Stacked Borrows; one for the expression `&mut y`, and another for the cast to `*mut T`.
```rust
let x = &mut y as *mut i32;
```
We would need an additional configuration flag to optionally support this behavior.

## Codegen
We need a way to lower MIR retags into a form that can be consumed by codegen backends. The easiest way to do this with the least impact on existing APIs is to emit retags as function calls. The underlying functions will not actually exist; the only purpose of these calls is to carry type and aliasing information, and it's expected that they will be transformed or intercepted by third-party tools.

A [`Place`](https://doc.rust-lang.org/beta/nightly-rustc/rustc_middle/mir/struct.Place.html) is a series of zero or more projections from a local variable. If a place has projections, then the pointer that we are retagging is not available yet; we need to load it from memory. Otherwise, we can access the pointer directly as an operand without having to do any extra work. Miri handles each of these cases using [`retag_place_contents`](https://doc.rust-lang.org/nightly/nightly-rustc/rustc_const_eval/interpret/trait.Machine.html#method.retag_place_contents) and [`retag_ptr_value`](https://doc.rust-lang.org/nightly/nightly-rustc/rustc_const_eval/interpret/trait.Machine.html#method.retag_ptr_value), respectively. This means that we need to emit retags in two different forms, depending on whether the pointer being retagged has been loaded from memory, or if it's in stored within a place. Each form will use a different function (shown in LLVM IR):
```llvm
ptr @__retag_operand(ptr)
void @__retag_place(ptr)
```
We describe the full signature of these intrinsic functions in the next section. For now, note that the parameter to `__retag_operand` is the pointer that receives the retag. We can see this in action with the following statement from our example:
```rust
let rx = &mut unsafe { *ptr_x };
```
This has the MIR:
```rust
tmp = &mut ptr_x;
Retag(tmp)
rx = move (tmp)
```
When this is compiled to LLVM IR, we will see:
```llvm
%rx = call ptr @__retag_operand(ptr %ptr_x)
```
Both `%rx` and `%ptr_x` will have the same address, but `%rx` is a different value; its provenance is different from that of `%ptr_x`. We do not specify the form that provenance metadata will take at this level. This is intentional, as there are multiple potential implementations; provenance could be stored [in shadow memory](https://valgrind.org/docs/shadow-memory2007.pdf), on the stack, or in the additional space afforded by [a wider pointer representation](https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/). Regardless, we assume that the third-party tools which consume these retags will use one of these mechanisms to associate each pointer with its provenance metadata.

When a place is retagged, the first parameter to `__retag_place` is the address of the location containing the pointer that needs to be retagged. Unlike operands, there is no return value here; provenance is updated in-place. Our example also uses `__retag_place`, but it needs special handling. Recall that MIR retags are coarse-grained; they specify that an entire place needs to be retagged, but only a subset of the fields or variants of that place will contain references. If a place contains multiple fields, then we recursively offset into the fields that need to be retagged, emitting a retag for each reference-type field. However, variants of enums are a bit more difficult. Consider the function-entry retag in our example:
```rust
fn example(x: Option<Box<i32>>) -> () {
    ...
    bb0: {
        Retag([fn entry] x);
```
We need to emit a function-entry retag for `x`, but this is only necessary if the `Option` contains a value. Miri can lookup the value stored in `x`, see which variant it has, and then perform the retag if necessary. We need to encode this branching logic into the compiled program. For example, the LLVM IR for the function `example` would need to look something like this:
```llvm
define void @example(ptr align 4 %0) {
start:
    %1 = ptrtoint ptr %0 to i64
    %2 = icmp eq i64 %1, 0
    %discr = select i1 %2, i64 0, i64 1
    br i1 %discr, label %is_some, label %next

is_some:                                    ; preds = %start
  call void @__retag_place(ptr %x)
  br label %next
  ...
}
next:
  ...
```
In this snippet, the function `example` receives a pointer (`%0`) to the place containing the value of `x`. The discriminant of `Option::Some` is 1, so if the register `%discr` is non-zero, then we know to branch to the block `%is_some`, where we retag the innermost pointer of the `Box`. Otherwise, we can continue on into the rest of the body of `example`.

# Reference-level explanation
Here, we describe each of the changes to the compiler that we will need to fully implement this feature.

## MIR-Level Changes
Outside of `rustc_codegen_ssa`, most of the semantic changes to the compiler will happen inside the [`AddRetag`](https://doc.rust-lang.org/nightly/nightly-rustc/rustc_mir_transform/add_retag/struct.AddRetag.html) MIR pass. This is enabled by the unstable flag `-Zmir-emit-retag`, which will now take three options:

* `partial` (default) - Nothing changes from the current behavior.
* `full` - Explicit retags will be emitted when references are created.
* `full-raw` - Explicit retags will be emitted when references are created and when they are cast into raw pointers.

In both the `full` and `full-raw` modes, we apply the transformation shown earlier, where temporary variables are introduced emit explicit retags for borrowing. All other significant changes to the compiler involve codegen.

## Codegen
Here, we propose a signature for our low-level retag intrinsics and outline how a single MIR-level [`Retag`] statement will be lowered into one or more intrinsic calls.

### Retag Intrinsics
Our low-level retags will have the following signature:
```llvm
ptr @__retag_operand(ptr, i64, i64, i8, ptr)
void @__retag_place(ptr, i64, i64, i8, ptr)
```
Aside from the first parameter, the remaining parameters have the same semantics for each function. Here, we describe them in order from left to right.

#### **Target** (`ptr`)
For `__retag_operand`, this is the pointer being retagged. The return value has the same address but carries updated provenance metadata. For `__retag_place`, the first parameter is the location where the pointer being retagged is stored, and the new permission is updated in-place.

#### **Size** - `i64`
An offset in bytes from the start of the pointer being retagged, indicating the valid range for the new permission. This is determined by the size of the pointee type for the pointer or reference being retagged.

#### **Permission Type** - `i64`

The kind of permission created by the retag operation. This should be equivalent to Miri's [`NewPermission`](https://github.com/rust-lang/miri/blob/7d5ae365eb1db28d15e540d43a50530a49512db4/src/borrow_tracker/tree_borrows/mod.rs#L118) serialized into a `u64`. This value will be computed using the following MIR query:
```
query retag_perm(key: (ty::TypingEnv<'tcx>, ty::Ty<'tcx>, RetagKind, Option<Mutability>)) -> Option<u64>
```
If the third parameter (`Option<Mutability>`) is `None`, then this indicates that we are retagging a `Box` or a raw pointer. Making this a compiler query allows third-party plugins to override its implementation.

#### **Function-Entry Flag** - `i8`

A flag indicating whether this is a function-entry retag. Permissions created by function-entry retags are placed in a "protected" state for the duration of the function—this requires explicit handling at runtime. Instrumentation tools can use this flag to easily identify which permissions need this special treatment. The permission type parameter will also include this information (e.g. [`ProtectorKind`](https://doc.rust-lang.org/beta/nightly-rustc/miri/borrow_tracker/enum.ProtectorKind.html)), but having this available as a flag will be easier to maintain in the long-term than requiring tool designers to decode the permission type field within, say, an LLVM instrumentation pass.

#### **Interior Mutability Range** - `ptr`
A pointer to a global constant array of pairs of `i64` values. Each pair consists of the offset and size of an interior mutable field within the pointee type.

Up until this point, we have relied on an overly simplified description of a borrow tag as uniquely identifying *a* permission. However, a single borrow tag will provide different capabilities depending on the range within the layout of the type that is being accessed. This is relevant for types that contain `UnsafeCell`, which provides interior mutability. For example, if we have a reference `x: &(u32, UnsafeCell<u32>)` then writing through `x.0` is undefined behavior, but we want to allow writing through `x.1`. To handle this, each retag needs to have access to the offsets and sizes of the fields of the pointee type that are covered by `UnsafeCell`. We will store this information as a constant array of pair of integers. Unlike for retags themselves,

We do not need to emit any additional branching to handle interior mutable enums, since if one variant contains an `UnsafeCell`, then the entire enum is considered interior mutable. We will provide a new unstable flag `-Zcodegen-retag-no-precise-interior-mut` to enable this behavior by default for all aggregate types, matching Miri's `-Zmiri-tree-borrows-no-precise-interior-mut` flag.

### Expanding Retags

During codegen, we will access an MIR-level place as either a [`PlaceRef`](https://doc.rust-lang.org/stable/nightly-rustc/rustc_codegen_ssa/mir/place/struct.PlaceRef.html) or an [`OperandRef`](https://doc.rust-lang.org/stable/nightly-rustc/rustc_codegen_ssa/mir/operand/struct.OperandRef.html), depending on whether the place has projections. However, the method we use for lowering will be the same for each representation. The first step in this process is to create a "retag plan", which will describe where references and `Box` instances live within the layout of the type of the place.
```rust
/// A description of the locations within a type that need retags.
enum RetagPlan {
    /// Indicates that a retag should be emitted. The first parameter is
    /// the size of the permission and the second is the result of the
    /// `retag_perm` query. The third parameter is the allocation ID of the
    /// global constant array describing the interior mutable fields within
    /// the pointee type of the reference or `Box` being retagged. This will be
    /// `None` if `-Zcodegen-retag-no-precise-interior-mut` is set or if the
    /// entire type is interior mutable.
    EmitRetag(Size, u64, Option<AllocId>),
    /// Indicates that one or more fields or variants of a type
    /// contain references that need to be retagged.
    Recurse(RetagLayout),
}
/// The set of fields and variants of a type that contain
/// references which need to be retagged.
struct RetagLayout {
    fields: IndexMap<FieldIdx, RetagPlan>,
    variants: IndexMap<VariantIdx, RetagPlan>,
}
```
By default, a `RetagPlan` will cover the full layout of a type. However, developers will also be able to adjust the precision of this step using a new unstable flag `-Zcodgen-retag-fields`, which will take three options:
* `all` (default) - Always recurse.
* `none` - Never recurse. Unsound.
* `scalar` - Only recurse into scalar values.
This matches Miri's [`-Zmiri-retag-fields`](https://github.com/rust-lang/miri/blob/7d5ae365eb1db28d15e540d43a50530a49512db4/README.md?plain=1#L467) flag.

After creating a `RetagPlan`, we will use it to guide how we project through the `PlaceRef` or `OperandRef` to emit each retag intrinsic call. When we reach `RetagPlan::Recurse`, we will create new basic blocks for each variant. After generating the blocks for each variant of a `RetagLayout`, we will emit a `br` or `switch` instruction to branch to each block, depending on how many variants are present. Each "variant block" will eventually branch to a single "terminator block". For example, if we were retagging a value of type `Either<A, B>`, where `A` and `B` both contain references, we will generate two variant blocks: one for the `Left` variant and another for the `Right` variant. We will `br` to either block, and then each block will branch to the same terminator block.

When we retag an `OperandRef`, we need to overwrite its value with the new alias created by `__retag_operand`. This is non-trivial for operands with variants, since each variant may or may not require overwriting the operand. Consider the type `Either<&i8, &mut i8>`. This type has a `ScalarPair` ABI, meaning that when we need to retag an operand with this type, we will access its value as an `OperandValue::ScalarPair(v1, v2)`. The first value is the discriminant of the enum, and the second is the pointer being retagged. If we retag an operand with this type, we will emit the following LLVM IR:
```
start:
  br i1 %discr, label %left, label %right

left:
  %alias1 = __retag_operand(%ptr, ...)
  br label %terminator

right:
  %alias2 = __retag_operand(%ptr, ...)
  br label %terminator
```
We know that the second component of the pair will need to be replaced with an alias, but we have two options; one for the `&i8` variant and another for the `&mut i8` variant. We can handle this by emitting a [`phi`](https://llvm.org/docs/LangRef.html#phi-instruction) node within the `%terminator` block.
```
%terminator:
  %alias = phi ptr [%alias1, %left], [%alias2, %right]
```
The value `%alias` will be equal to `%alias1` if we came from the `%left` block and `alias2` if we came from the `%right` block.

