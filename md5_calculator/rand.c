#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main(){
	int seed;
	int random[8];
	int result;
	
	// set past time (i.e. -1 second) as seed
	//seed = time(0);
	seed = time(0) - 1;
	srand(seed);
	
	// generate 8 random numbers
	for (int i = 0; i < 8; i++) {
		random[i] = rand();
		printf("random[%d]: %d\n", i, random[i]);
	}

	// compute results for calculating canary
	result = 0 - random[1] - random[2] + random[3] - random[4] - random[5] + random[6] - random[7];
	printf("==> result: %d\n", result);

	return 0;
}
