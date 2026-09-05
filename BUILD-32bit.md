# Building Sotoportego on 32-bit Haiku (x86)

Sotoportego builds and runs on 32-bit Haiku too. It just needs one extra habit:
run every build command under `setarch x86`. Here's why, and the exact steps.

## Why `setarch x86`?

The standard 32-bit Haiku image is a **"hybrid" (gcc2h)** system: the legacy
**gcc2** is the *primary* compiler and a **modern gcc** is the *secondary* one.
Sotoportego uses modern C++, which **gcc2 cannot compile**. `setarch x86`
switches your shell to the secondary (modern) toolchain, so the build uses the
right compiler. Just prefix your commands with it — that's the whole trick.

## 1. Confirm you're on 32-bit Haiku

```
getarch
```

`getarch` reports the architecture of your current shell:

* **`x86_gcc2`** → you're on the standard 32-bit (hybrid) image. This is the
  usual case; keep going and use `setarch x86` as shown below.
* **`x86`** → you're on a 32-bit image where the modern gcc is already primary.
  You can build directly; the `setarch x86` prefix is harmless, so the steps
  below still work as-is.
* **`x86_64`** → you're on 64-bit. This guide isn't for you; use the normal
  [Build section of the README](README.md#build).

## 2. Install the build dependencies

You need `git` and the OpenSSL 3 **development** package for the secondary
(x86) architecture:

```
pkgman install git openssl3_x86_devel
```

On a hybrid system, packages for the secondary architecture carry the **`_x86`**
suffix, which is why it's `openssl3_x86_devel` and not `openssl3_devel`. If
`pkgman` says it can't find that exact name, list what's available and pick the
`openssl3…x86…devel` one:

```
pkgman search openssl3
```

(On a non-hybrid x86 image, drop the suffix: `pkgman install openssl3_devel`.)

## 3. Get the source

```
git clone https://github.com/atomozero/Sotoportego.git
cd Sotoportego
```

## 4. Build

Prefix the build with `setarch x86` so it uses the modern gcc:

```
setarch x86 make
```

This builds the daemon, the CLI and the GUI. The binaries land in each
subdirectory's `objects.x86-*-release/` folder. To start clean later:

```
setarch x86 make clean
```

## 5. (Optional) Build an installable package

```
setarch x86 ./scripts/make-hpkg.sh
```

The script detects the architecture from the shell (`x86` under `setarch`), so
it writes `dist/sotoportego-<version>-x86.hpkg` with the right architecture set.
Install it with:

```
pkgman install dist/sotoportego-*-x86.hpkg
```

…or drop the `.hpkg` into `~/config/packages/`.

## 6. Run

If you didn't build the package, launch the GUI straight from the build folder:

```
./src/gui/objects.x86-*-release/Sotoportego
```

It starts the background daemon automatically.

## Troubleshooting

* **C++ errors right at the start of the build** (unknown types, `-std=`
  complaints, template failures) → gcc2 is compiling the code. You forgot the
  `setarch x86` prefix, or your shell's `getarch` still reports `x86_gcc2`.
  Re-run with `setarch x86` in front.
* **Linker error: `cannot find -lcrypto` / `-lssl`** → the OpenSSL 3 devel
  package for x86 is missing. Install it (see step 2).
* **`make-hpkg.sh` produced a `…-x86_gcc2.hpkg`** → you ran it without
  `setarch x86`, so it picked up the primary architecture. Run
  `setarch x86 ./scripts/make-hpkg.sh`.
