# Simple function trace tools

A simple instrumentation-based trace tool for my own analysis needs.

## Usage

### Prepare

Add `xray` compiler flag to `.cargo/config.toml`

```toml
rustflags = [
  "-Zinstrument-xray=always",
]
```

Add setup crate

```toml
[dependencies]
sftrace-setup = { path = "../sftrace/setup" }
```

Initialize sftrace, which should be run before anything else

```rust
fn main() {
  unsafe {
    sftrace_setup::setup();
  }
}

// or

#[ctor]
unsafe fn init_sftrace() {
  unsafe {
    sftrace_setup::setup();
  }
}
```

If you need to record memory events,
and need to configure the global allocator hook

```rust
#[global_allocator]
static A: sftrace_setup::SftraceAllocator<std::alloc::System> =
  sftrace_setup::SftraceAllocator(std::alloc::System);
```

The setup crate does not provide symbols to link against,
you can point it to so. or simply allow symbols to be undefined.

```toml
[target.'cfg(target_os = "linux")']
rustflags = [ "-Clink-args=-Wl,--warn-unresolved-symbols" ]

[target.'cfg(target_vendor = "apple")']
rustflags = [ "-Clink-args=-Wl,-undefined,dynamic_lookup" ]
```

### Run

Run the program on specified environment variables

```shell
env LD_PRELOAD="$TOPATH/libsftrace.so" \
  SFTRACE_OUTPUT_FILE="$OUTDIR/sf.log" \
  your-program
```

Note that this may generate very large logs, which may require a lot of memory when analyzing.
You can generate filter files to keep only the functions you are interested in.

```shell
sftrace filter -p your-program -o "$OUTDIR/sf.filter" -r $TARGET_DIR'/deps/libyour*.rlib'
```

Specify the filter file when running the program

```shell
env ... \
  SFTRACE_FILTER="$OUTDIR/sf.filter" \
  your-program
```

### macOS

We support macOS, but macOS doesn't support us.

You need to run the program on lldb (or any ptrace debugger).

```shell
lldb \
    -O "env DYLD_INSERT_LIBRARIES=$TOPATH/libsftrace.dylib" \
    -O "env SFTRACE_OUTPUT_FILE=$OUTDIR/sf.log" \
    your-program
```

This is because the text segment can only be modified in
[ptrace](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.101.15/bsd/kern/mach_process.c#L212)
(and [dtrace](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.101.15/bsd/dev/dtrace/fasttrap.c#L564)).

### Analyze

You can convert it to perfetto protobuf format

```shell
sftrace convert "$OUTDIR/sf.log" -o trace.pb.gz
```

and I recommend using [vizviewr](https://github.com/gaogaotiantian/viztracer)

```shell
vizviewer --use_external_processor trace.pb.gz
```
