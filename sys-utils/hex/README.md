## hex encode/decode tool

### Requirements

- Docker >= 18.x
- GNU Make >= 3.81

### Building

```bash
$ cd sys-utils/hex
$ make
```

#### Makefile targets

The following options are available as `make` targets:

- **all**: builds the RISC-V hex executable
- **extra.ext2**: builds the extra.ext2 filesystem image with the hex tool inside
- **toolchain-env**: runs the toolchain image with current user UID and GID
- **clean**: clean generated artifacts

#### Makefile container options

You can pass the following variables to the make target if you wish to use different docker image tags.

- TOOLCHAIN\_IMAGE: toolchain image name
- TOOLCHAIN\_TAG: toolchain image tag

```
$ make TOOLCHAIN_TAG=mytag
```

It's useful when you want to use prebuilt images like `cartesi/toolchain:latest`

#### Usage

The purpose of the hex tool please see the emulator documentation.

The purpose of the `extra.ext2` image is to help the development creating a filesystem that contains the hex tool so it can be used with the emulator. For instructions on how to do that, please see the emulator documentation.
