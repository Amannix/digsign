#include <stdio.h>
#include <time.h>

/************************************************************************
 ** 函数名:     get_sys_runtime
 ** 函数描述:   返回系统运行时间
 ** 参数:       [in]  1 - 秒,2 - 毫秒
 ** 返回:       秒/毫秒
 ************************************************************************/
static long get_sys_runtime(int type)
{
	struct timespec times = {0, 0};
	long time;

	clock_gettime(CLOCK_MONOTONIC, &times);
	printf("CLOCK_MONOTONIC: %lu, %lu\n", times.tv_sec, times.tv_nsec);

	if (1 == type){
		time = times.tv_sec;
	}else{
		time = times.tv_sec * 1000 + times.tv_nsec / 1000000;
	}
	
	printf("time = %ld\n", time);
    return time;
}

int main(int argc,char *argv[])
{
	printf ("test");
	exit(0);
	/*long sec, millisecond;
	sec = get_sys_runtime(1);
	millisecond = get_sys_runtime(2);
	printf("sec = %ld, millisecond = %ld\n", sec, millisecond);*/
	return 0;
}
