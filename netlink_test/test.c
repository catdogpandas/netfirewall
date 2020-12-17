#include <stdio.h>

int main() {
  unsigned int a = 1;
  printf("%x\n", (a << 31) - 1);
}