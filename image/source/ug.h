#pragma once

bool ugProbe(int chan);
int ugSend(int chan, const void *data, int len);
int ugRecv(int chan, void *data, int len);
int ugSendBlocking(int chan, const void *data, int len);
int ugRecvBlocking(int chan, void *data, int len);
