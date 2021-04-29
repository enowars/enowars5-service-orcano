#include "sleep.h"
#include "util.h"

#include <time.h>
#include <ogc/system.h>

#include <cstdint>

static syswd_t g_sleep_alarm;

OC_INIT_FUNCTION()
{
	SYS_CreateAlarm(&g_sleep_alarm);
}

static volatile bool g_sleep_done;

void sleepNs(uint64_t ns)
{
	constexpr uint64_t k_ns_per_sec = 1000 * 1000 * 1000;
	struct timespec sleep_duration;
	sleep_duration.tv_sec = ns / k_ns_per_sec;
	sleep_duration.tv_nsec = ns % k_ns_per_sec;

	// Set 
	g_sleep_done = false;
	SYS_SetAlarm(
		g_sleep_alarm,
		&sleep_duration,
		[](syswd_t alarm, void *user)
		{
			g_sleep_done = true;
		},
		nullptr
	);

	// Wait for alarm
	// Dolphin should be able to idle-skip this busy-loop.
	while (!g_sleep_done);
}

void sleepMs(int ms)
{
	constexpr uint64_t k_ns_per_ms = 1000 * 1000;
	sleepNs(ms * k_ns_per_ms);
}