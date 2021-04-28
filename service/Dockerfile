FROM orcano-dolphin

# Configure Dolphin
# Careful: ~ doesn't work here!
RUN mkdir /root/.dolphin-emu
COPY Config /root/.dolphin-emu/Config

# Configure service
WORKDIR /service
RUN mkdir data
COPY service.py image.dol .

# Set unbuffered mode so we get stdout
ENV PYTHONUNBUFFERED=1
CMD [ "python3", "service.py" ]