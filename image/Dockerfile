FROM devkitpro/devkitppc:20190212

WORKDIR /image
COPY . .
RUN make

RUN /opt/devkitpro/devkitPPC/bin/powerpc-eabi-readelf -s -W image.elf | grep FUNC | sort -k 2,2 > image.map