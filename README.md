# Read_cpuutil
Program to read CPU utilization

Task here is to compute CPU utilization using mpstat or systat framework.

### Completed:
- Added makefile to build project.
- Added cpu_util.h containing API to call get_cpu_util_perc to get CPUUTIL in \%.

### ToDo:
- Add the master-slave model to call and set frequency using CPU UTIL from the slaves.
- Bind each slave to it's cpus/cores.
- Define model or topology between each slaves.
