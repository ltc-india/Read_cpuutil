#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct stats_cpu {
	unsigned long long cpu_user;
	unsigned long long cpu_nice;
	unsigned long long cpu_sys;
	unsigned long long cpu_idle;
	unsigned long long cpu_iowait;
	unsigned long long cpu_steal;
	unsigned long long cpu_hardirq;
	unsigned long long cpu_softirq;
	unsigned long long cpu_guest;
	unsigned long long cpu_guest_nice;
}; 

struct stats_cpu cur,prev;

#define STAT "/proc/stat"

double get_cpu_util_perc(int cpu_id);
