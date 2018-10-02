#include <cpu_util.h>

int read_stat_cpu(struct stats_cpu *st_cpu, int cpu_id)
{
	FILE *fp;
	struct stats_cpu *st_cpu_i;
	struct stats_cpu sc;
	char line[8192];
	int proc_nr;
	int cpu_read = 0;

	if ((fp = fopen(STAT, "r")) == NULL) {
		exit(2);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {

		if (!strncmp(line, "cpu ", 4)) {
			/*
			 * For aggregated all cpu utilization
			 * skip if not asked for.
			 * cpu_id indicates the cpu on which we want to monitor.
			 * -1 for all cpus.
			 */
			if(cpu_id!=-1)
				continue;

			/*
			 * All the fields don't necessarily exist,
			 * depending on the kernel version used.
			 */
			memset(st_cpu, 0, sizeof(struct stats_cpu));

			/*
			 * Read the number of jiffies spent in the different modes
			 * (user, nice, etc.) among all proc. CPU usage is not reduced
			 * to one processor to avoid rounding problems.
			 */
			sscanf(line + 5, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			       &st_cpu->cpu_user,
			       &st_cpu->cpu_nice,
			       &st_cpu->cpu_sys,
			       &st_cpu->cpu_idle,
			       &st_cpu->cpu_iowait,
			       &st_cpu->cpu_hardirq,
			       &st_cpu->cpu_softirq,
			       &st_cpu->cpu_steal,
			       &st_cpu->cpu_guest,
			       &st_cpu->cpu_guest_nice);

			if (!cpu_read) {
				cpu_read = 1;
			}

		}

		else if (!strncmp(line, "cpu", 3)) {
			int cpu_dump;
			if(cpu_id != atoi(line+3))
				continue;
			/* All the fields don't necessarily exist */
			memset(&sc, 0, sizeof(struct stats_cpu));
			/*
			 * Read the number of jiffies spent in the different modes
			 * (user, nice, etc) for current proc.
			 * This is done only on SMP machines.
			 */
			sscanf(line + 3, "%d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			       &cpu_dump,
			       &st_cpu->cpu_user,
			       &st_cpu->cpu_nice,
			       &st_cpu->cpu_sys,
			       &st_cpu->cpu_idle,
			       &st_cpu->cpu_iowait,
			       &st_cpu->cpu_hardirq,
			       &st_cpu->cpu_softirq,
			       &st_cpu->cpu_steal,
			       &st_cpu->cpu_guest,
			       &st_cpu->cpu_guest_nice);
		}
	}

	fclose(fp);
	return cpu_read;
}

double calc_util_perc(struct stats_cpu prev, struct stats_cpu cur){
	unsigned long prev_total = 0, cur_total=0;
	prev_total =  prev.cpu_user + prev.cpu_nice + prev.cpu_sys + prev.cpu_idle
	       	+ prev.cpu_iowait + prev.cpu_steal + prev.cpu_hardirq 
		+ prev.cpu_softirq + prev.cpu_guest + prev.cpu_guest_nice;
	cur_total = cur.cpu_user + cur.cpu_nice + cur.cpu_sys + cur.cpu_idle 
		+ cur.cpu_iowait + cur.cpu_steal + cur.cpu_hardirq 
		+ cur.cpu_softirq + cur.cpu_guest + cur.cpu_guest_nice;

	if(cur_total-prev_total <= 0)
		return 0;
	return ((1-(cur.cpu_idle-prev.cpu_idle)*1.0/(cur_total-prev_total))*100);
}

void copy_struct(struct stats_cpu src, struct stats_cpu *dest){
	dest->cpu_user = src.cpu_user;
	dest->cpu_nice = src.cpu_nice;
	dest->cpu_sys = src.cpu_sys;
	dest->cpu_idle = src.cpu_idle;
	dest->cpu_steal = src.cpu_steal;
	dest->cpu_hardirq = src.cpu_hardirq;
	dest->cpu_softirq = src.cpu_softirq;
	dest->cpu_guest = src.cpu_guest;
	dest->cpu_guest_nice = src.cpu_guest_nice;
}

double get_cpu_util_perc(int cpu_id){
	double utilization = 0;
	read_stat_cpu(&prev, cpu_id);
	sleep(1);
	read_stat_cpu(&cur, cpu_id);
	utilization = calc_util_perc(prev, cur);
	copy_struct(cur, &prev);
	return utilization;
}
