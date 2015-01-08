#include "he_math.h"
#include <cstdio>
#include <cstdlib>

int main(int argc, char **argv){
	HE_fix a(1.5);
	HE_fix b(-2.7);
	HE_fix c = a + b;
	printf("%f\n", c.decode());
	return 0;
}
