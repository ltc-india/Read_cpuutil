#include <cpu_util.h>

int main(int argc, char** argv){
	int cpu = -1;
	if(argc>1){
		sscanf(argv[0],"%d",&cpu);
	}

	while(1){
		printf("%lf\n",get_cpu_util_perc(cpu));
		sleep(1);
	}
	return 0;
}
