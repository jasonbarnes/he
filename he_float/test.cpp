#include <cstdio>
#include "binary_he_float.h"

int main(int argc, char **argv){
	HE_float Xa((float)2.8);
	printf("%f\n", Xa.extract());
	//XXX
}
