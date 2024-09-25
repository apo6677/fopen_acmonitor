#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <gmp.h>
#include <time.h>

int main() 
{
	unsigned long int w = 1;
	int u = 0;

	unsigned long int P, D, E, N= 0;
	unsigned long int Q = 0;
	unsigned long int ii, iii = 0;
	unsigned long int plnchr, cphchr = 0;

	int A = 0;
	int B = 0;
	int C = 0;
	int eflag = 0;
	
	mpz_t p, q, n, lambda, e, flag2, flag1, d, I, k, l;

	mpz_init(p);
	mpz_init(d);
	mpz_init(q);
	mpz_init(n);
	mpz_init(lambda);
	mpz_init(e);
	mpz_init(flag2);
	mpz_init(flag1);
	mpz_init(I);
	mpz_init(k);
	mpz_init(l);

	char* pub_k = "public.key";
	char* pr_k = "private.key";

	printf("If you want to encrypt all entries type 1\n");
	scanf("%d", &eflag);

//step 1 and 2
	if(eflag == 1){
		printf("Give the first prime number, p:\n");
		scanf("%ld", &P);
		printf("Give the second prime number, q:\n");
		scanf("%ld", &Q);

		mpz_set_ui(p,P);
		mpz_set_ui(q,Q);
			
		//step 3
		mpz_mul(n, p, q);

		//step 4
		mpz_set_ui(I,w);
		mpz_sub(k, p, I);
		mpz_sub(l, q, I);

		mpz_mul(lambda, k, l);
		unsigned long int L = mpz_get_ui(lambda);

		//step 5
		while(B==0){
			srand(time(NULL));
			unsigned long int E	= rand()%(L - w + 1) + w;
			mpz_set_ui(e,E);

			u = mpz_probab_prime_p(e, 48);
			if(u == 2){			
				mpz_gcd(flag2, e, lambda);
				if(mpz_get_ui(flag2)==1){
					mpz_mod(flag1, e, lambda);
					if(mpz_get_ui(flag1)!=0){B = 1;}
				}
				if(B==0){mpz_add(e, e, I);}
			}
	
		}
		mpz_invert(d, e, lambda);

		N = mpz_get_ui(n);
		E = mpz_get_ui(e);
		D = mpz_get_ui(d);

		FILE* file1 = fopen(pub_k, "w");
		fprintf(file1, "%ld, %ld", N, D);
		fclose(file1);

		file1 = fopen(pr_k, "w");
		fprintf(file1, "%ld, %ld", N, E);
		fclose(file1);
	}

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


}
