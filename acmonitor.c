#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <gmp.h>
#include <openssl/md5.h>

struct entry {

	long int uid; /* user id (positive integer) */
	long int access_type; /* access type values [0-2] */
	long int action_denied; /* is action denied values [0-1] */

	const char *date; /* file access date */
	time_t time; /* file access time */

	const char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{

	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{	mpz_t n, d;
	mpz_init(d);
	mpz_init(n);
	FILE* file = fopen("private.key", "r");
	int ii = 0;
	int iii = 0;

	if(file == NULL){
		printf("\nUnable to open file");
	}

//process to recover the private key begins----------------------------------------------------------------

	ii = fgetc(file);
	while(ii!= 44){
	if(ii!=44){iii = 10*iii + ii - 48;}
		ii = fgetc(file);
	}
		
	mpz_set_ui(n,iii);
	printf("%d is n\n", iii);

	fgetc(file); // to get the space after the coma (,) at file private.key, whose ascii number is 44, to get the first character of the private key

	iii = 0;
	while(ii!= EOF){
		if(ii!=44){iii = 10*iii + ii - 48;}
		ii = fgetc(file);
	}

	mpz_set_ui(d,iii);
	printf("%d is d\n", iii);

	fclose(file);
//process to recover the private key is ended----------------------------------------------------------------

	int fingerprint1[5];
	int a=0;
	int b=0;
	iii = 0;
	ii = 0;
	while(a!=6){
		printf("f\n");
		if(ii==10){
			a++;
		}
		if(a==6){
			while(ii!=10){
				printf("%d", ii);
				iii = 10*iii + ii - 48;
				fingerprint1[b] = iii;
				printf("%d\n", fingerprint1[b]);
				b++;
				ii = fgetc(log);
			}
		}
		ii = fgetc(log);
	}

	//printf("%s\n", (char)fingerprint1);

	return;
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2){
		usage();
	}

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
