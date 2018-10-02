/*
 * mpstat: per-processor statistics
 * (C) 2000-2018 by Sebastien GODARD (sysstat <at> orange.fr)
 *
 ***************************************************************************
 * This program is free software; you can redistribute it and/or modify it *
 * under the terms of the GNU General Public License as published  by  the *
 * Free Software Foundation; either version 2 of the License, or (at  your *
 * option) any later version.                                              *
 *                                                                         *
 * This program is distributed in the hope that it  will  be  useful,  but *
 * WITHOUT ANY WARRANTY; without the implied warranty  of  MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License *
 * for more details.                                                       *
 *                                                                         *
 * You should have received a copy of the GNU General Public License along *
 * with this program; if not, write to the Free Software Foundation, Inc., *
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA              *
 ***************************************************************************
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/utsname.h>

#include "mpstat.h"
#include "common.h"
#include "rd_stats.h"
#include "count.h"

#include <locale.h>	/* For setlocale() */
#ifdef USE_NLS
#include <libintl.h>
#define _(string) gettext(string)
#else
#define _(string) (string)
#endif

unsigned long long uptime_cs[3] = {0, 0, 0};

/* NOTE: Use array of _char_ for bitmaps to avoid endianness problems...*/
unsigned char *cpu_bitmap;	/* Bit 0: Global; Bit 1: 1st proc; etc. */
unsigned char *node_bitmap;	/* Bit 0: Global; Bit 1: 1st NUMA node; etc. */

/* Structures used to save CPU and NUMA nodes CPU stats */
struct stats_cpu *st_cpu[3];
struct stats_cpu *st_node[3];

/*
 * Structure used to save total number of interrupts received
 * among all CPU and for each CPU.
 */
struct stats_irq *st_irq[3];

/*
 * Structures used to save, for each interrupt, the number
 * received by each CPU.
 */
struct stats_irqcpu *st_irqcpu[3];
struct stats_irqcpu *st_softirqcpu[3];

/*
 * Number of CPU per node, e.g.:
 * cpu_per_node[0]: total nr of CPU (this is node "all")
 * cpu_per_node[1]: nr of CPU for node 0
 * etc.
 */
int *cpu_per_node;

/*
 * Node number the CPU belongs to, e.g.:
 * cpu2node[0]: node nr for CPU 0
 */
int *cpu2node;

struct tm mp_tstamp[3];

/* Activity flag */
unsigned int actflags = 0;

unsigned int flags = 0;

/* Interval and count parameters */
long interval = -1, count = 0;
/* Number of decimal places */
int dplaces_nr = -1;

/*
 * Nb of processors on the machine.
 * A value of 2 means there are 2 processors (0 and 1).
 */
int cpu_nr = 0;

/*
 * Highest NUMA node number found on the machine.
 * A value of 0 means node 0 (one node).
 * A value of -1 means no nodes found.
 * We have: node_nr < cpu_nr (see get_node_placement() function).
 */
int node_nr = -1;

/* Nb of interrupts per processor */
int irqcpu_nr = 0;
/* Nb of soft interrupts per processor */
int softirqcpu_nr = 0;

struct sigaction alrm_act, int_act;
int sigint_caught = 0;

/*
 ***************************************************************************
 * Print usage and exit
 *
 * IN:
 * @progname	Name of sysstat command
 ***************************************************************************
 */
void usage(char *progname)
{
	fprintf(stderr, _("Usage: %s [ options ] [ <interval> [ <count> ] ]\n"),
		progname);

	fprintf(stderr, _("Options are:\n"
			  "[ -A ] [ -n ] [ -u ] [ -V ]\n"
			  "[ -I { SUM | CPU | SCPU | ALL } ] [ -N { <node_list> | ALL } ]\n"
			  "[ --dec={ 0 | 1 | 2 } ] [ -o JSON ] [ -P { <cpu_list> | ALL } ]\n"));
	exit(1);
}

/*
 ***************************************************************************
 * SIGALRM signal handler. No need to reset the handler here.
 *
 * IN:
 * @sig	Signal number.
 ***************************************************************************
 */
void alarm_handler(int sig)
{
	alarm(interval);
}

/*
 ***************************************************************************
 * SIGINT signal handler.
 *
 * IN:
 * @sig	Signal number.
 **************************************************************************
 */
void int_handler(int sig)
{
	sigint_caught = 1;
}

/*
 ***************************************************************************
 * Allocate stats structures and cpu bitmap. Also do it for NUMA nodes
 * (although the machine may not be a NUMA one). Assume that the number of
 * nodes is lower or equal than that of CPU.
 *
 * IN:
 * @nr_cpus	Number of CPUs. This is the real number of available CPUs + 1
 * 		because we also have to allocate a structure for CPU 'all'.
 ***************************************************************************
 */
void salloc_mp_struct(int nr_cpus)
{
	int i;

	for (i = 0; i < 3; i++) {

		if ((st_cpu[i] = (struct stats_cpu *) malloc(STATS_CPU_SIZE * nr_cpus))
		    == NULL) {
			perror("malloc");
			exit(4);
		}
		memset(st_cpu[i], 0, STATS_CPU_SIZE * nr_cpus);

		if ((st_node[i] = (struct stats_cpu *) malloc(STATS_CPU_SIZE * nr_cpus))
		    == NULL) {
			perror("malloc");
			exit(4);
		}
		memset(st_node[i], 0, STATS_CPU_SIZE * nr_cpus);

		if ((st_irq[i] = (struct stats_irq *) malloc(STATS_IRQ_SIZE * nr_cpus))
		    == NULL) {
			perror("malloc");
			exit(4);
		}
		memset(st_irq[i], 0, STATS_IRQ_SIZE * nr_cpus);

		if ((st_irqcpu[i] = (struct stats_irqcpu *) malloc(STATS_IRQCPU_SIZE * nr_cpus * irqcpu_nr))
		    == NULL) {
			perror("malloc");
			exit(4);
		}
		memset(st_irqcpu[i], 0, STATS_IRQCPU_SIZE * nr_cpus * irqcpu_nr);

		if ((st_softirqcpu[i] = (struct stats_irqcpu *) malloc(STATS_IRQCPU_SIZE * nr_cpus * softirqcpu_nr))
		     == NULL) {
			perror("malloc");
			exit(4);
		}
		memset(st_softirqcpu[i], 0, STATS_IRQCPU_SIZE * nr_cpus * softirqcpu_nr);
	}

	if ((cpu_bitmap = (unsigned char *) malloc((nr_cpus >> 3) + 1)) == NULL) {
		perror("malloc");
		exit(4);
	}
	memset(cpu_bitmap, 0, (nr_cpus >> 3) + 1);

	if ((node_bitmap = (unsigned char *) malloc((nr_cpus >> 3) + 1)) == NULL) {
		perror("malloc");
		exit(4);
	}
	memset(node_bitmap, 0, (nr_cpus >> 3) + 1);

	if ((cpu_per_node = (int *) malloc(sizeof(int) * nr_cpus)) == NULL) {
		perror("malloc");
		exit(4);
	}

	if ((cpu2node = (int *) malloc(sizeof(int) * nr_cpus)) == NULL) {
		perror("malloc");
		exit(4);
	}
}

/*
 ***************************************************************************
 * Free structures and bitmap.
 ***************************************************************************
 */
void sfree_mp_struct(void)
{
	int i;

	for (i = 0; i < 3; i++) {
		free(st_cpu[i]);
		free(st_node[i]);
		free(st_irq[i]);
		free(st_irqcpu[i]);
		free(st_softirqcpu[i]);
	}

	free(cpu_bitmap);
	free(node_bitmap);
	free(cpu_per_node);
	free(cpu2node);
}

/*
 ***************************************************************************
 * Get node placement (which node each CPU belongs to, and total number of
 * CPU that each node has).
 *
 * IN:
 * @cpu_nr		Number of CPU on this machine.
 *
 * OUT:
 * @cpu_per_node	Number of CPU per node.
 * @cpu2node		The node the CPU belongs to.
 *
 * RETURNS:
 * Highest node number found (e.g., 0 means node 0).
 * A value of -1 means no nodes have been found.
 ***************************************************************************
 */
int get_node_placement(int cpu_nr, int cpu_per_node[], int cpu2node[])

{
	DIR *dir;
	struct dirent *drd;
	char line[MAX_PF_NAME];
	int cpu, node, node_nr = -1;

	/* Init number of CPU per node */
	memset(cpu_per_node, 0, sizeof(int) * (cpu_nr + 1));
	/* CPU belongs to no node by default */
	memset(cpu2node, -1, sizeof(int) * cpu_nr);

	/* This is node "all" */
	cpu_per_node[0] = cpu_nr;

	for (cpu = 0; cpu < cpu_nr; cpu++) {
		snprintf(line, MAX_PF_NAME, "%s/cpu%d", SYSFS_DEVCPU, cpu);
		line[MAX_PF_NAME - 1] = '\0';

		/* Open relevant /sys directory */
		if ((dir = opendir(line)) == NULL)
			return -1;

		/* Get current file entry */
		while ((drd = readdir(dir)) != NULL) {

			if (!strncmp(drd->d_name, "node", 4) && isdigit(drd->d_name[4])) {
				node = atoi(drd->d_name + 4);
				if ((node >= cpu_nr) || (node < 0)) {
					/* Assume we cannot have more nodes than CPU */
					closedir(dir);
					return -1;
				}
				cpu_per_node[node + 1]++;
				cpu2node[cpu] = node;
				if (node > node_nr) {
					node_nr = node;
				}
				/* Node placement found for current CPU: Go to next CPU directory */
				break;
			}
		}

		/* Close directory */
		closedir(dir);
	}

	return node_nr;
}

/*
 ***************************************************************************
 * Compute node statistics: Split CPU statistics among nodes.
 *
 * IN:
 * @src		Structure containing CPU stats to add.
 *
 * OUT:
 * @dest	Structure containing global CPU stats.
 ***************************************************************************
 */
void add_cpu_stats(struct stats_cpu *dest, struct stats_cpu *src)
{
	dest->cpu_user       += src->cpu_user;
	dest->cpu_nice       += src->cpu_nice;
	dest->cpu_sys        += src->cpu_sys;
	dest->cpu_idle       += src->cpu_idle;
	dest->cpu_iowait     += src->cpu_iowait;
	dest->cpu_hardirq    += src->cpu_hardirq;
	dest->cpu_softirq    += src->cpu_softirq;
	dest->cpu_steal      += src->cpu_steal;
	dest->cpu_guest      += src->cpu_guest;
	dest->cpu_guest_nice += src->cpu_guest_nice;
}

/*
 ***************************************************************************
 * Compute node statistics: Split CPU statistics among nodes.
 *
 * IN:
 * @prev	Index in array where stats used as reference are.
 * @curr	Index in array for current sample statistics.
 *
 * OUT:
 * @st_node	Array where CPU stats for each node have been saved.
 ***************************************************************************
 */
void set_node_cpu_stats(int prev, int curr)
{
	int cpu;
	unsigned long long tot_jiffies_p;
	struct stats_cpu *scp, *scc, *snp, *snc;
	struct stats_cpu *scc_all = st_cpu[curr];
	struct stats_cpu *scp_all = st_cpu[prev];
	struct stats_cpu *snc_all = st_node[curr];
	struct stats_cpu *snp_all = st_node[prev];

	/* Reset structures */
	memset(st_node[prev], 0, STATS_CPU_SIZE * (cpu_nr + 1));
	memset(st_node[curr], 0, STATS_CPU_SIZE * (cpu_nr + 1));

	/* Node 'all' is the same as CPU 'all' */
	*snp_all = *scp_all;
	*snc_all = *scc_all;

	/* Individual nodes */
	for (cpu = 0; cpu < cpu_nr; cpu++) {
		scc = st_cpu[curr] + cpu + 1;
		scp = st_cpu[prev] + cpu + 1;
		snp = st_node[prev] + cpu2node[cpu] + 1;
		snc = st_node[curr] + cpu2node[cpu] + 1;


		tot_jiffies_p = scp->cpu_user + scp->cpu_nice +
				scp->cpu_sys + scp->cpu_idle +
				scp->cpu_iowait + scp->cpu_hardirq +
				scp->cpu_steal + scp->cpu_softirq;
		if ((tot_jiffies_p == 0) && (interval != 0))
			/*
			 * CPU has just come back online with no ref from
			 * previous iteration: Skip it.
			 */
			continue;

		add_cpu_stats(snp, scp);
		add_cpu_stats(snc, scc);
	}
}

/*
 ***************************************************************************
 * Compute global CPU statistics as the sum of individual CPU ones, and
 * calculate interval for global CPU.
 * Also identify offline CPU.
 *
 * IN:
 * @prev	Index in array where stats used as reference are.
 * @curr	Index in array for current sample statistics.
 * @offline_cpu_bitmap
 *		CPU bitmap for offline CPU.
 *
 * OUT:
 * @offline_cpu_bitmap
 *		CPU bitmap with offline CPU.
 *
 * RETURNS:
 * Interval for global CPU.
 ***************************************************************************
 */
unsigned long long get_global_cpu_mpstats(int prev, int curr,
					  unsigned char offline_cpu_bitmap[])
{
	int i;
	unsigned long long tot_jiffies_c, tot_jiffies_p;
	unsigned long long deltot_jiffies = 0;
	struct stats_cpu *scc, *scp;
	struct stats_cpu *scc_all = st_cpu[curr];
	struct stats_cpu *scp_all = st_cpu[prev];

	/*
	 * For UP machines we keep the values read from global CPU line in /proc/stat.
	 * Also look for offline CPU: They won't be displayed, and some of their values may
	 * have to be modified.
	 */
	if (cpu_nr > 1) {
		memset(scc_all, 0, sizeof(struct stats_cpu));
		memset(scp_all, 0, sizeof(struct stats_cpu));
	}
	else {
		/* This is a UP machine */
		return get_per_cpu_interval(st_cpu[curr], st_cpu[prev]);
	}

	for (i = 1; i <= cpu_nr; i++) {

		scc = st_cpu[curr] + i;
		scp = st_cpu[prev] + i;

		/*
		 * Compute the total number of jiffies spent by current processor.
		 * NB: Don't add cpu_guest/cpu_guest_nice because cpu_user/cpu_nice
		 * already include them.
		 */
		tot_jiffies_c = scc->cpu_user + scc->cpu_nice +
				scc->cpu_sys + scc->cpu_idle +
				scc->cpu_iowait + scc->cpu_hardirq +
				scc->cpu_steal + scc->cpu_softirq;
		tot_jiffies_p = scp->cpu_user + scp->cpu_nice +
				scp->cpu_sys + scp->cpu_idle +
				scp->cpu_iowait + scp->cpu_hardirq +
				scp->cpu_steal + scp->cpu_softirq;

		/*
		 * If the CPU is offline then it is omited from /proc/stat:
		 * All the fields couldn't have been read and the sum of them is zero.
		 */
		if (tot_jiffies_c == 0) {
			/*
			 * CPU is currently offline.
			 * Set current struct fields (which have been set to zero)
			 * to values from previous iteration. Hence their values won't
			 * jump from zero when the CPU comes back online.
			 * Note that this workaround no longer fully applies with recent kernels,
			 * as I have noticed that when a CPU comes back online, some fields
			 * restart from their previous value (e.g. user, nice, system)
			 * whereas others restart from zero (idle, iowait)! To deal with this,
			 * the get_per_cpu_interval() function will set these previous values
			 * to zero if necessary.
			 */
			*scc = *scp;

			/*
			 * Mark CPU as offline to not display it
			 * (and thus it will not be confused with a tickless CPU).
			 */
			offline_cpu_bitmap[i >> 3] |= 1 << (i & 0x07);
		}

		if ((tot_jiffies_p == 0) && (interval != 0)) {
			/*
			 * CPU has just come back online.
			 * Unfortunately, no reference values are available
			 * from a previous iteration, probably because it was
			 * already offline when the first sample has been taken.
			 * So don't display that CPU to prevent "jump-from-zero"
			 * output syndrome, and don't take it into account for CPU "all".
			 * NB: Test for interval != 0 to make sure we don't want stats
			 * since boot time.
			 */
			offline_cpu_bitmap[i >> 3] |= 1 << (i & 0x07);
			continue;
		}

		/*
		 * Get interval for current CPU and add it to global CPU.
		 * Note: Previous idle and iowait values (saved in scp) may be modified here.
		 */
		deltot_jiffies += get_per_cpu_interval(scc, scp);

		add_cpu_stats(scc_all, scc);
		add_cpu_stats(scp_all, scp);
	}

	return deltot_jiffies;
}

/*
 ***************************************************************************
 * Display CPU statistics in plain format.
 *
 * IN:
 * @dis		TRUE if a header line must be printed.
 * @deltot_jiffies
 *		Number of jiffies spent on the interval by all processors.
 * @prev	Position in array where statistics used	as reference are.
 *		Stats used as reference may be the previous ones read, or
 *		the very first ones when calculating the average.
 * @curr	Position in array where current statistics will be saved.
 * @prev_string	String displayed at the beginning of a header line. This is
 * 		the timestamp of the previous sample, or "Average" when
 * 		displaying average stats.
 * @curr_string	String displayed at the beginning of current sample stats.
 * 		This is the timestamp of the current sample, or "Average"
 * 		when displaying average stats.
 * @offline_cpu_bitmap
 *		CPU bitmap for offline CPU.
 ***************************************************************************
 */
void write_plain_cpu_stats(int dis, unsigned long long deltot_jiffies, int prev, int curr,
			   char *prev_string, char *curr_string, unsigned char offline_cpu_bitmap[])
{
	int i;
	struct stats_cpu *scc, *scp;

	if (dis) {
		printf("\n%-11s  CPU    %%usr   %%nice    %%sys %%iowait    %%irq   "
		       "%%soft  %%steal  %%guest  %%gnice   %%idle\n",
		       prev_string);
	}

	/*
	 * Now display CPU statistics (including CPU "all"),
	 * except for offline CPU or CPU that the user doesn't want to see.
	 */
	for (i = 0; i <= cpu_nr; i++) {

		/* Check if we want stats about this proc */
		if (!(*(cpu_bitmap + (i >> 3)) & (1 << (i & 0x07))) ||
		    offline_cpu_bitmap[i >> 3] & (1 << (i & 0x07)))
			continue;

		scc = st_cpu[curr] + i;
		scp = st_cpu[prev] + i;

		printf("%-11s", curr_string);

		if (i == 0) {
			/* This is CPU "all" */
			cprintf_in(IS_STR, " %s", " all", 0);
		}
		else {
			cprintf_in(IS_INT, " %4d", "", i - 1);

			/* Recalculate itv for current proc */
			deltot_jiffies = get_per_cpu_interval(scc, scp);

			if (!deltot_jiffies) {
				/*
				 * If the CPU is tickless then there is no change in CPU values
				 * but the sum of values is not zero.
				 */
				cprintf_pc(NO_UNIT, 10, 7, 2,
					   0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 100.0);
				printf("\n");

				continue;
			}
		}

		cprintf_pc(NO_UNIT, 10, 7, 2,
			   (scc->cpu_user - scc->cpu_guest) < (scp->cpu_user - scp->cpu_guest) ?
			   0.0 :
			   ll_sp_value(scp->cpu_user - scp->cpu_guest,
				       scc->cpu_user - scc->cpu_guest, deltot_jiffies),
			   (scc->cpu_nice - scc->cpu_guest_nice) < (scp->cpu_nice - scp->cpu_guest_nice) ?
			   0.0 :
			   ll_sp_value(scp->cpu_nice - scp->cpu_guest_nice,
				       scc->cpu_nice - scc->cpu_guest_nice, deltot_jiffies),
			   ll_sp_value(scp->cpu_sys,
				       scc->cpu_sys, deltot_jiffies),
			   ll_sp_value(scp->cpu_iowait,
				       scc->cpu_iowait, deltot_jiffies),
			   ll_sp_value(scp->cpu_hardirq,
				       scc->cpu_hardirq, deltot_jiffies),
			   ll_sp_value(scp->cpu_softirq,
				       scc->cpu_softirq, deltot_jiffies),
			   ll_sp_value(scp->cpu_steal,
				       scc->cpu_steal, deltot_jiffies),
			   ll_sp_value(scp->cpu_guest,
				       scc->cpu_guest, deltot_jiffies),
			   ll_sp_value(scp->cpu_guest_nice,
				       scc->cpu_guest_nice, deltot_jiffies),
			   (scc->cpu_idle < scp->cpu_idle) ?
			   0.0 :
			   ll_sp_value(scp->cpu_idle,
				       scc->cpu_idle, deltot_jiffies));
		printf("\n");
	}
}
/*
 ***************************************************************************
 * Display CPU statistics in plain or JSON format.
 *
 * IN:
 * @dis		TRUE if a header line must be printed.
 * @deltot_jiffies
 *		Number of jiffies spent on the interval by all processors.
 * @prev	Position in array where statistics used	as reference are.
 *		Stats used as reference may be the previous ones read, or
 *		the very first ones when calculating the average.
 * @curr	Position in array where current statistics will be saved.
 * @prev_string	String displayed at the beginning of a header line. This is
 * 		the timestamp of the previous sample, or "Average" when
 * 		displaying average stats.
 * @curr_string	String displayed at the beginning of current sample stats.
 * 		This is the timestamp of the current sample, or "Average"
 * 		when displaying average stats.
 * @tab		Number of tabs to print (JSON format only).
 * @next	TRUE is a previous activity has been displayed (JSON format
 * 		only).
 * @offline_cpu_bitmap
 *		CPU bitmap for offline CPU.
 ***************************************************************************
 */
void write_cpu_stats(int dis, unsigned long long deltot_jiffies, int prev, int curr,
		     char *prev_string, char *curr_string, int tab, int *next,
		     unsigned char offline_cpu_bitmap[])
{
	if (!deltot_jiffies) {
		/* CPU "all" cannot be tickless */
		deltot_jiffies = 1;
	}
	write_plain_cpu_stats(dis, deltot_jiffies, prev, curr,
				      prev_string, curr_string, offline_cpu_bitmap);
}

/*
 ***************************************************************************
 * Print statistics average.
 *
 * IN:
 * @curr	Position in array where statistics for current sample are.
 * @dis		TRUE if a header line must be printed.
 ***************************************************************************
 */
void write_stats_avg(int curr, int dis)
{
	char string[16];

	strncpy(string, _("Average:"), 16);
	string[15] = '\0';
}

/*
 ***************************************************************************
 * Print statistics.
 *
 * IN:
 * @curr	Position in array where statistics for current sample are.
 * @dis		TRUE if a header line must be printed.
 ***************************************************************************
 */
void write_stats(int curr, int dis)
{
	char cur_time[2][TIMESTAMP_LEN];

	/* Get previous timestamp */
	if (is_iso_time_fmt()) {
		strftime(cur_time[!curr], sizeof(cur_time[!curr]), "%H:%M:%S", &mp_tstamp[!curr]);
	}
	else {
		strftime(cur_time[!curr], sizeof(cur_time[!curr]), "%X", &(mp_tstamp[!curr]));
	}

	/* Get current timestamp */
	if (is_iso_time_fmt()) {
		strftime(cur_time[curr], sizeof(cur_time[curr]), "%H:%M:%S", &mp_tstamp[curr]);
	}
	else {
		strftime(cur_time[curr], sizeof(cur_time[curr]), "%X", &(mp_tstamp[curr]));
	}

}

/*
 ***************************************************************************
 * Read stats from /proc/interrupts or /proc/softirqs.
 *
 * IN:
 * @file	/proc file to read (interrupts or softirqs).
 * @ic_nr	Number of interrupts (hard or soft) per CPU.
 * @curr	Position in array where current statistics will be saved.
 *
 * OUT:
 * @st_ic	Array for per-CPU interrupts statistics.
 ***************************************************************************
 */
void read_interrupts_stat(char *file, struct stats_irqcpu *st_ic[], int ic_nr, int curr)
{
	FILE *fp;
	struct stats_irq *st_irq_i;
	struct stats_irqcpu *p;
	char *line = NULL, *li;
	unsigned long irq = 0;
	unsigned int cpu;
	int cpu_index[cpu_nr], index = 0, len;
	char *cp, *next;

	/* Reset total number of interrupts received by each CPU */
	for (cpu = 0; cpu < cpu_nr; cpu++) {
		st_irq_i = st_irq[curr] + cpu + 1;
		st_irq_i->irq_nr = 0;
	}

	if ((fp = fopen(file, "r")) != NULL) {

		SREALLOC(line, char, INTERRUPTS_LINE + 11 * cpu_nr);

		/*
		 * Parse header line to see which CPUs are online
		 */
		while (fgets(line, INTERRUPTS_LINE + 11 * cpu_nr, fp) != NULL) {
			next = line;
			while (((cp = strstr(next, "CPU")) != NULL) && (index < cpu_nr)) {
				cpu = strtol(cp + 3, &next, 10);
				cpu_index[index++] = cpu;
			}
			if (index)
				/* Header line found */
				break;
		}

		/* Parse each line of interrupts statistics data */
		while ((fgets(line, INTERRUPTS_LINE + 11 * cpu_nr, fp) != NULL) &&
		       (irq < ic_nr)) {

			/* Skip over "<irq>:" */
			if ((cp = strchr(line, ':')) == NULL)
				/* Chr ':' not found */
				continue;
			cp++;

			p = st_ic[curr] + irq;

			/* Remove possible heading spaces in interrupt's name... */
			li = line;
			while (*li == ' ')
				li++;

			len = strcspn(li, ":");
			if (len >= MAX_IRQ_LEN) {
				len = MAX_IRQ_LEN - 1;
			}
			/* ...then save its name */
			strncpy(p->irq_name, li, len);
			p->irq_name[len] = '\0';

			/* For each interrupt: Get number received by each CPU */
			for (cpu = 0; cpu < index; cpu++) {
				p = st_ic[curr] + cpu_index[cpu] * ic_nr + irq;
				st_irq_i = st_irq[curr] + cpu_index[cpu] + 1;
				/*
				 * No need to set (st_irqcpu + cpu * irqcpu_nr)->irq_name:
				 * This is the same as st_irqcpu->irq_name.
				 * Now save current interrupt value for current CPU (in stats_irqcpu structure)
				 * and total number of interrupts received by current CPU (in stats_irq structure).
				 */
				p->interrupt = strtoul(cp, &next, 10);
				st_irq_i->irq_nr += p->interrupt;
				cp = next;
			}
			irq++;
		}

		fclose(fp);

		free(line);
	}

	while (irq < ic_nr) {
		/* Nb of interrupts per processor has changed */
		p = st_ic[curr] + irq;
		p->irq_name[0] = '\0';	/* This value means this is a dummy interrupt */
		irq++;
	}
}

/*
 ***************************************************************************
 * Main loop: Read stats from the relevant sources, and display them.
 *
 * IN:
 * @dis_hdr	Set to TRUE if the header line must always be printed.
 * @rows	Number of rows of screen.
 ***************************************************************************
 */
void rw_mpstat_loop(int dis_hdr, int rows)
{
	struct stats_cpu *scc;
	int i;
	int curr = 1, dis = 1;
	unsigned long lines = rows;

	/* Dont buffer data if redirected to a pipe */
	setbuf(stdout, NULL);

	/* Read system uptime and CPU stats */
	read_uptime(&(uptime_cs[0]));
	read_stat_cpu(st_cpu[0], cpu_nr + 1);

	/*
	 * Calculate global CPU stats as the sum of individual ones.
	 * Done only on SMP machines. On UP machines, we keep the values
	 * read from /proc/stat for global CPU stats.
	 */
	if (cpu_nr > 1) {
		memset(st_cpu[0], 0, STATS_CPU_SIZE);

		for (i = 1; i <= cpu_nr; i++) {
			scc = st_cpu[0] + i;

			st_cpu[0]->cpu_user += scc->cpu_user;
			st_cpu[0]->cpu_nice += scc->cpu_nice;
			st_cpu[0]->cpu_sys += scc->cpu_sys;
			st_cpu[0]->cpu_idle += scc->cpu_idle;
			st_cpu[0]->cpu_iowait += scc->cpu_iowait;
			st_cpu[0]->cpu_hardirq += scc->cpu_hardirq;
			st_cpu[0]->cpu_steal += scc->cpu_steal;
			st_cpu[0]->cpu_softirq += scc->cpu_softirq;
			st_cpu[0]->cpu_guest += scc->cpu_guest;
			st_cpu[0]->cpu_guest_nice += scc->cpu_guest_nice;
		}
	}

	/*
	 * Read total number of interrupts received among all CPU.
	 * (this is the first value on the line "intr:" in the /proc/stat file).
	 */
	if (DISPLAY_IRQ_SUM(actflags)) {
		read_stat_irq(st_irq[0], 1);
	}

	/*
	 * Read number of interrupts received by each CPU, for each interrupt,
	 * and compute the total number of interrupts received by each CPU.
	 */
	if (DISPLAY_IRQ_SUM(actflags) || DISPLAY_IRQ_CPU(actflags)) {
		/* Read this file to display int per CPU or total nr of int per CPU */
		read_interrupts_stat(INTERRUPTS, st_irqcpu, irqcpu_nr, 0);
	}
	if (DISPLAY_SOFTIRQS(actflags)) {
		read_interrupts_stat(SOFTIRQS, st_softirqcpu, softirqcpu_nr, 0);
	}

	if (!interval) {
		/* Display since boot time */
		mp_tstamp[1] = mp_tstamp[0];
		memset(st_cpu[1], 0, STATS_CPU_SIZE * (cpu_nr + 1));
		memset(st_node[1], 0, STATS_CPU_SIZE * (cpu_nr + 1));
		memset(st_irq[1], 0, STATS_IRQ_SIZE * (cpu_nr + 1));
		memset(st_irqcpu[1], 0, STATS_IRQCPU_SIZE * (cpu_nr + 1) * irqcpu_nr);
		if (DISPLAY_SOFTIRQS(actflags)) {
			memset(st_softirqcpu[1], 0, STATS_IRQCPU_SIZE * (cpu_nr + 1) * softirqcpu_nr);
		}
		write_stats(0, DISP_HDR);
		if (DISPLAY_JSON_OUTPUT(flags)) {
			printf("\n\t\t\t]\n\t\t}\n\t]\n}}\n");
		}
		exit(0);
	}

	/* Set a handler for SIGALRM */
	memset(&alrm_act, 0, sizeof(alrm_act));
	alrm_act.sa_handler = alarm_handler;
	sigaction(SIGALRM, &alrm_act, NULL);
	alarm(interval);

	/* Save the first stats collected. Will be used to compute the average */
	mp_tstamp[2] = mp_tstamp[0];
	uptime_cs[2] = uptime_cs[0];
	memcpy(st_cpu[2], st_cpu[0], STATS_CPU_SIZE * (cpu_nr + 1));
	memcpy(st_node[2], st_node[0], STATS_CPU_SIZE * (cpu_nr + 1));
	memcpy(st_irq[2], st_irq[0], STATS_IRQ_SIZE * (cpu_nr + 1));
	memcpy(st_irqcpu[2], st_irqcpu[0], STATS_IRQCPU_SIZE * (cpu_nr + 1) * irqcpu_nr);
	if (DISPLAY_SOFTIRQS(actflags)) {
		memcpy(st_softirqcpu[2], st_softirqcpu[0],
		       STATS_IRQCPU_SIZE * (cpu_nr + 1) * softirqcpu_nr);
	}

	if (!DISPLAY_JSON_OUTPUT(flags)) {
		/* Set a handler for SIGINT */
		memset(&int_act, 0, sizeof(int_act));
		int_act.sa_handler = int_handler;
		sigaction(SIGINT, &int_act, NULL);
	}

	pause();

	if (sigint_caught)
		/* SIGINT signal caught during first interval: Exit immediately */
		return;

	do {
		/*
		 * Resetting the structure not needed since every fields will be set.
		 * Exceptions are per-CPU structures: Some of them may not be filled
		 * if corresponding processor is disabled (offline). We set them to zero
		 * to be able to distinguish between offline and tickless CPUs.
		 */
		memset(st_cpu[curr], 0, STATS_CPU_SIZE * (cpu_nr + 1));

		/* Get time */
		get_localtime(&(mp_tstamp[curr]), 0);

		/* Read uptime and CPU stats */
		read_uptime(&(uptime_cs[curr]));
		read_stat_cpu(st_cpu[curr], cpu_nr + 1);

		/* Read total number of interrupts received among all CPU */
		if (DISPLAY_IRQ_SUM(actflags)) {
			read_stat_irq(st_irq[curr], 1);
		}

		/*
		 * Read number of interrupts received by each CPU, for each interrupt,
		 * and compute the total number of interrupts received by each CPU.
		 */
		if (DISPLAY_IRQ_SUM(actflags) || DISPLAY_IRQ_CPU(actflags)) {
			read_interrupts_stat(INTERRUPTS, st_irqcpu, irqcpu_nr, curr);
		}
		if (DISPLAY_SOFTIRQS(actflags)) {
			read_interrupts_stat(SOFTIRQS, st_softirqcpu, softirqcpu_nr, curr);
		}

		/* Write stats */
		if (!dis_hdr) {
			dis = lines / rows;
			if (dis) {
				lines %= rows;
			}
			lines++;
		}
		write_stats(curr, dis);

		if (count > 0) {
			count--;
		}

		if (count) {

			if (DISPLAY_JSON_OUTPUT(flags)) {
				printf(",\n");
			}
			pause();

			if (sigint_caught) {
				/* SIGINT signal caught => Display average stats */
				count = 0;
				printf("\n");	/* Skip "^C" displayed on screen */
			}
			else {
				curr ^= 1;
			}
		}
	}
	while (count);

	/* Write stats average */
	if (DISPLAY_JSON_OUTPUT(flags)) {
		printf("\n\t\t\t]\n\t\t}\n\t]\n}}\n");
	}
	else {
		write_stats_avg(curr, dis_hdr);
	}
}

/*
 ***************************************************************************
 * Main entry to the program
 ***************************************************************************
 */
int main(int argc, char **argv)
{
	int opt = 0, i, actset = FALSE;
	struct utsname header;
	int dis_hdr = -1;
	int rows = 23;
	char *t;

#ifdef USE_NLS
	/* Init National Language Support */
	init_nls();
#endif

	/* Init color strings */
	init_colors();

	/* Get HZ */
	get_HZ();

	/* What is the highest processor number on this machine? */
	cpu_nr = get_cpu_nr(~0, TRUE);

	/* Calculate number of interrupts per processor */
	irqcpu_nr = get_irqcpu_nr(INTERRUPTS, NR_IRQS, cpu_nr) +
		    NR_IRQCPU_PREALLOC;
	/* Calculate number of soft interrupts per processor */
	softirqcpu_nr = get_irqcpu_nr(SOFTIRQS, NR_IRQS, cpu_nr) +
			NR_IRQCPU_PREALLOC;

	/*
	 * cpu_nr: a value of 2 means there are 2 processors (0 and 1).
	 * In this case, we have to allocate 3 structures: global, proc0 and proc1.
	 */
	salloc_mp_struct(cpu_nr + 1);

	/* Get NUMA node placement */
	node_nr = get_node_placement(cpu_nr, cpu_per_node, cpu2node);

	while (++opt < argc) {

		if (!strncmp(argv[opt], "--dec=", 6) && (strlen(argv[opt]) == 7)) {
			/* Get number of decimal places */
			dplaces_nr = atoi(argv[opt] + 6);
			if ((dplaces_nr < 0) || (dplaces_nr > 2)) {
				usage(argv[0]);
			}
		}

		else if (!strcmp(argv[opt], "-I")) {
			if (!argv[++opt]) {
				usage(argv[0]);
			}
			actset = TRUE;

			for (t = strtok(argv[opt], ","); t; t = strtok(NULL, ",")) {
				if (!strcmp(t, K_SUM)) {
					/* Display total number of interrupts per CPU */
					actflags |= M_D_IRQ_SUM;
				}
				else if (!strcmp(t, K_CPU)) {
					/* Display interrupts per CPU */
					actflags |= M_D_IRQ_CPU;
				}
				else if (!strcmp(t, K_SCPU)) {
					/* Display soft interrupts per CPU */
					actflags |= M_D_SOFTIRQS;
				}
				else if (!strcmp(t, K_ALL)) {
					actflags |= M_D_IRQ_SUM + M_D_IRQ_CPU + M_D_SOFTIRQS;
				}
				else {
					usage(argv[0]);
				}
			}
		}

		else if (!strcmp(argv[opt], "-o")) {
			/* Select output format */
			if (argv[++opt] && !strcmp(argv[opt], K_JSON)) {
				flags |= F_JSON_OUTPUT;
			}
			else {
				usage(argv[0]);
			}
		}

		else if (!strcmp(argv[opt], "-N")) {
			if (!argv[++opt]) {
				usage(argv[0]);
			}
			if (node_nr >= 0) {
				flags |= F_N_OPTION;
				actflags |= M_D_NODE;
				actset = TRUE;
				dis_hdr = 9;
				if (parse_values(argv[opt], node_bitmap, node_nr + 1, K_LOWERALL)) {
					usage(argv[0]);
				}
			}
		}

		else if (!strcmp(argv[opt], "-P")) {
			/* '-P ALL' can be used on UP machines */
			if (!argv[++opt]) {
				usage(argv[0]);
			}
			flags |= F_P_OPTION;
			dis_hdr = 9;

			if (parse_values(argv[opt], cpu_bitmap, cpu_nr, K_LOWERALL)) {
				usage(argv[0]);
			}
		}

		else if (!strncmp(argv[opt], "-", 1)) {
			for (i = 1; *(argv[opt] + i); i++) {

				switch (*(argv[opt] + i)) {

				case 'A':
					actflags |= M_D_CPU + M_D_IRQ_SUM + M_D_IRQ_CPU + M_D_SOFTIRQS;
					if (node_nr >= 0) {
						actflags |= M_D_NODE;
						flags |= F_N_OPTION;
						memset(node_bitmap, 0xff, ((cpu_nr + 1) >> 3) + 1);
					}
					actset = TRUE;
					/* Select all processors */
					flags |= F_P_OPTION;
					memset(cpu_bitmap, 0xff, ((cpu_nr + 1) >> 3) + 1);
					break;

				case 'n':
					/* Display CPU stats based on NUMA node placement */
					if (node_nr >= 0) {
						actflags |= M_D_NODE;
						actset = TRUE;
					}
					break;

				case 'u':
					/* Display CPU */
					actflags |= M_D_CPU;
					break;

				case 'V':
					/* Print version number */
					print_version();
					break;

				default:
					usage(argv[0]);
				}
			}
		}

		else if (interval < 0) {
			/* Get interval */
			if (strspn(argv[opt], DIGITS) != strlen(argv[opt])) {
				usage(argv[0]);
			}
			interval = atol(argv[opt]);
			if (interval < 0) {
				usage(argv[0]);
			}
			count = -1;
		}

		else if (count <= 0) {
			/* Get count value */
			if ((strspn(argv[opt], DIGITS) != strlen(argv[opt])) ||
			    !interval) {
				usage(argv[0]);
			}
			count = atol(argv[opt]);
			if (count < 1) {
				usage(argv[0]);
			}
		}

		else {
			usage(argv[0]);
		}
	}

	/* Default: Display CPU (e.g., "mpstat", "mpstat -P 1", "mpstat -P 1 -n", "mpstat -P 1 -N 1"... */
	if (!actset ||
	    (USE_P_OPTION(flags) && !(actflags & ~M_D_NODE))) {
		actflags |= M_D_CPU;
	}

	if (count_bits(&actflags, sizeof(unsigned int)) > 1) {
		dis_hdr = 9;
	}

	if (!USE_P_OPTION(flags)) {
		/* Option -P not used: Set bit 0 (global stats among all proc) */
		*cpu_bitmap = 1;
	}
	if (!USE_N_OPTION(flags)) {
		/* Option -N not used: Set bit 0 (global stats among all nodes) */
		*node_bitmap = 1;
	}
	if (dis_hdr < 0) {
		dis_hdr = 0;
	}
	if (!dis_hdr) {
		/* Get window size */
		rows = get_win_height();
	}
	if (interval < 0) {
		/* Interval not set => display stats since boot time */
		interval = 0;
	}

	if (DISPLAY_JSON_OUTPUT(flags)) {
		/* Use a decimal point to make JSON code compliant with RFC7159 */
		setlocale(LC_NUMERIC, "C");
	}

	/* Get time */
	get_localtime(&(mp_tstamp[0]), 0);

	/* Get system name, release number and hostname */
	uname(&header);
	print_gal_header(&(mp_tstamp[0]), header.sysname, header.release,
			 header.nodename, header.machine, get_cpu_nr(~0, FALSE),
			 DISPLAY_JSON_OUTPUT(flags));

	/* Main loop */
	rw_mpstat_loop(dis_hdr, rows);

	/* Free structures */
	sfree_mp_struct();

	return 0;
}
