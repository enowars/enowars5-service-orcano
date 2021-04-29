#pragma once

// Sleep functions that play nicely with Dolphin idle-skipping to minimize our
// performance impact when idle

void sleepNs(int ns);
void sleepMs(int ms);