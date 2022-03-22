#include <stdio.h>
void main() {
	unsigned short v1, v2;

	printf("%10c%hn%10c%hn\n", 'a', &v1, 'b', &v2);
	printf("v1=%d, v2=%d\n", v1, v2);
	printf("%10c%3$hn%2$10c%4$hn\n", 'a', 'b', &v1, &v2);
	printf("v1=%d, v2=%d\n", v1, v2);
}
