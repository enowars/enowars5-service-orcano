# Build Dolphin
# https://dolphin-emu.org/docs/guides/building-dolphin-linux/
FROM ubuntu:21.04

# Set DEBIAN_FRONTEND to avoid tzdata install prompt
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	ca-certificates \
	qtbase5-dev \
	qtbase5-private-dev \
	git \
	cmake \
	make \
	gcc \
	g++ \
	pkg-config \
	libavcodec-dev \
	libavformat-dev \
	libavutil-dev \
	libswscale-dev \
	libxi-dev \
	libxrandr-dev \
	libudev-dev \
	libevdev-dev \
	libsfml-dev \
	libminiupnpc-dev \
	libmbedtls-dev \
	libcurl4-openssl-dev \
	libhidapi-dev \
	libsystemd-dev \
	libbluetooth-dev \
	libasound2-dev \
	libpulse-dev \
	libpugixml-dev \
	libbz2-dev \
	libzstd-dev \
	liblzo2-dev \
	libpng-dev \
	libusb-1.0-0-dev \
	gettext

# Get the code
WORKDIR /dolphin-build
RUN git clone https://github.com/dolphin-emu/dolphin.git
WORKDIR dolphin
# Just pin some recent version for now
# https://github.com/dolphin-emu/dolphin/commit/18174d3ed64f117baa755ec961345ee362a7ccc3
RUN git checkout 18174d3ed64f117baa755ec961345ee362a7ccc3

# Apply patches
RUN apt-get install -y --no-install-recommends patch
COPY dolphin.patch .
RUN patch -p 2 -i dolphin.patch

# Compile
RUN mkdir build
WORKDIR build
RUN cmake -DCMAKE_INSTALL_PREFIX=/dolphin -DENABLE_QT=OFF -DENABLE_EVDEV=OFF ..
RUN make -j6
RUN make install

# Cleanup (removes ~500M so worth it)
WORKDIR /
RUN rm -r dolphin-build
ENV DOLPHIN_EMU_NOGUI=/dolphin/bin/dolphin-emu-nogui