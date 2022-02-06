#include <stdio.h>
#include <stdlib.h>


int main() {

    setvbuf(stdout, NULL, _IONBF, 0);

    int i = 0;
 
    while (1==1) {

    srand(i);
    int key0 = rand() == 306291429;
    int key1 = rand() == 442612432;
    int key2 = rand() == 110107425;

    if (key0 && key1 && key2) {
        printf("seed = %i",i);
        exit(0);
    } 
    else {
     i = i +1;
    }
   }
}
