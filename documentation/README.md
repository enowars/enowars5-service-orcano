# Orcano

## Overview

Orcano implements what is in effect a fancy calculator. It's built as a hybrid int32/float32 stack machine that interprets small snippets of code. Code consists of a space-separated list of commands. In addition to offering stateless calculation, the service provides permanent storage of numbers through set/get commands. User accounts are identified by a 64-bit "username" and are authenticated either through a fixed 64-bit passsword or through an OTP scheme.

The service is implemented as a GameCube executable running inside the Dolphin emulator. A Python frontend implements all the necessary host functionality including networking, session management, crypto and disk access. It also enforces the OTP authentication method. The frontend communicates with the GameCube-side (hereafter "backend") via a USB Gecko peripheral configured into the emulator which is essentially just a serial port exposed as a local TCP socket.

Requests are queued in the frontend and then passed serially to a worker process running the backend in Dolphin. The emulator was patched to facilitate this usage: 
* A DMA mode of operation was added to the serial port to improve performance
* CPU usage and latency of the serial port driver was dramatically decreased through improved blocking behavior
* Port assignment was made configurable via command line to allow multiple instances of the emulator to run at the same time

The frontend and backend communicate via a simple message protocol consisting of a message type, size, and data blob. Requests are subject to strict 250ms timeouts. If the emulator does not complete the request within 250ms or responds in an invalid way, the emulator is killed and restarted.

## Directory structure
* `service` - frontend and final redistributable deployed on vulnboxes
* `image` - GameCube backend
* `dolphin` - patches and Dockerfile for the emulator
* `checker` - checker

## Flags

Flags are stored as numbers under random users. The flags are split into two flagstores: the users for the first use regular password authentication, the ones for the second use OTP. Flags are split into three-character groups, ASCII-encoded and converted to big-endian integers. These are then stored in ascending order from offset zero in the flag account. The usernames for these accounts are provided to players via attack info.

## Vulnerabilities

### OTP not invalidated on error
Commands using the OTP set `m_otp_touched` which will in turn dispatch an OTP invalidate message to the frontend after completion of the command. However, crucially this code is placed after the `break` from the interpreter loop, which means that in case of an error, the OTP will not be invalidated. 

By filling the stack, the `otp_sync` command will lead to a stack overflow error, leaking the secret due to be pushed. We can repeat this process for the other half and then sign in using the leaked code.

### `CustomArgParser::setText` off-by-one
There is an off-by-one in the size check in `CustomArgParser::setText`. This leads to the `m_gqr_dirty` variable being reset as it is overwritten with the null terminator of the string. This leads to the GQR state not being restored when the `CustomArgParser` goes out of scope.

We can abuse this by using a `weight` command with exactly 256 characters, triggering the off-by-one and setting the GQR mode to Int8. This means that `getUInt` for paired immediates can return negative values. We can abuse this by using an `inspect` command. This sends a variable amount of data. By passing a negative number to one of the counts, the size sent will be mismatched with the amount of data sent. We can encode a message of our choosing (like a get number query) in this excess data and bypass the user authentication.