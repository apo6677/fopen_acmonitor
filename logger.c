#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
	unsigned char *fingerprint; /* file fingerprint */
};

FILE *
fopen(const char *path, const char *mode) 
{
	FILE *log;
	long int filesize;
	unsigned char *buf;
	unsigned char *md5_result;
	int eflag  = 0;

	FILE *original_fopen_ret, *ori;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	ori = original_fopen_ret;

	if(strcmp(path,"./file_logging.log")==0 || strcmp(path,"public.key")==0 || strcmp(path,"private.key")==0){
		return original_fopen_ret;
	}

	printf("Please type 1 again to have the entries encrypted\n");
	scanf("%d", &eflag);

	mpz_t n, e, plainchar, cipherchar;
	int iii = 0;
	int ii = 0;

	mpz_init(n);
	mpz_init(e);
	mpz_init(plainchar);
	mpz_init(cipherchar);

	if(eflag == 1){
	//process to recover the public key begins----------------------------------------------------------------
		FILE* file2 = fopen("public.key", "r");			//public key file is opened
		if(file2 == NULL){
			printf("\nUnable to open file");	
		}

		ii = fgetc(file2);
		while(ii!= 44){
			if(ii!=44){
				iii = 10*iii + ii - 48;
			}
			ii = fgetc(file2);
		}
		mpz_set_ui(n,iii);

		fgetc(file2); // to get the space after the coma (,) at file private.key, whose ascii number is 44, to get the first character of the private key

		iii = 0;
		while(ii!= EOF){
			if(ii!=44){iii = 10*iii + ii - 48;}
			ii = fgetc(file2);
		}
		mpz_set_ui(e,iii);

		fclose(file2);
	}
	//process to recover the public key is ended----------------------------------------------------------------

	struct entry an_entry;
	an_entry.uid = getuid();
	an_entry.file = path;
	an_entry.time = time(NULL);

	fseek(ori,0L, SEEK_END);
	filesize = ftell(ori);
	fseek(ori, 0L, SEEK_SET);
	buf = malloc(filesize);
	fread(buf, filesize, 1, ori);
	md5_result = malloc(MD5_DIGEST_LENGTH);
	MD5(buf, filesize, md5_result);
	an_entry.fingerprint = md5_result;
	
	if(ori == NULL){
		an_entry.action_denied = 1;
	}
	an_entry.action_denied = 0; 

	an_entry.access_type = 0; // file creation if it isn't deleted or opened
	if(strcmp(mode, "r") == 0 || strcmp(mode, "r+") == 0){
		an_entry.access_type = 1; // file open
	}
	if(access(path, F_OK) == 0){
		if(strcmp(mode, "w") == 0 || strcmp(mode, "w+") == 0){
			an_entry.access_type = 3; // file deletion
		}
	}

//-------------------------------------------------------------------------------------------------------------------------------

	if(eflag == 1){
		mpz_set_ui(plainchar,an_entry.uid);			//encrypt uid
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.uid = mpz_get_ui(cipherchar);

		mpz_set_ui(plainchar,an_entry.time);			//encrypt time and therefore date is also changed...
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.time = mpz_get_ui(cipherchar);

		mpz_set_ui(plainchar,an_entry.access_type);			//encrypt access type
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.access_type = mpz_get_ui(cipherchar);

		mpz_set_ui(plainchar,an_entry.action_denied);			//encrypt action denied flag
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.action_denied = mpz_get_ui(cipherchar);
	}

	log = fopen("./file_logging.log", "a");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
	}
	fprintf(log, "%ld\n",an_entry.uid);
	fprintf(log, "%s\n",an_entry.file);
	fprintf(log, "%s",ctime(&an_entry.time));
	fprintf(log, "%lu\n",(unsigned long)an_entry.time);
	fprintf(log, "%ld\n",an_entry.access_type);
	fprintf(log, "%ld\n",an_entry.action_denied);
	fprintf(log, "%s\n\n",an_entry.fingerprint);
	printf("%s\n", path);
	fclose(log);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	int eflag = 0;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	
	FILE *log;
	long int filesize;
	unsigned char *buf;
	unsigned char *md5_result;

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	printf("Please type 1 again to have the entries encrypted\n");
	scanf("%d", &eflag);

	mpz_t n, e, plainchar, cipherchar;
	int iii = 0;
	int ii = 0;

	mpz_init(n);
	mpz_init(e);
	mpz_init(plainchar);
	mpz_init(cipherchar);

	if(eflag == 1){
	//process to recover the public key begins----------------------------------------------------------------
		FILE* file2 = fopen("public.key", "r");			//public key file is opened
		if(file2 == NULL){
			printf("\nUnable to open file");	
		}

		ii = fgetc(file2);
		while(ii!= 44){
			if(ii!=44){
				iii = 10*iii + ii - 48;
			}
			ii = fgetc(file2);
		}
		mpz_set_ui(n,iii);

		fgetc(file2); // to get the space after the coma (,) at file private.key, whose ascii number is 44, to get the first character of the private key

		iii = 0;
		while(ii!= EOF){
			if(ii!=44){iii = 10*iii + ii - 48;}
			ii = fgetc(file2);
		}
		mpz_set_ui(e,iii);

		fclose(file2);
	}
	//process to recover the public key is ended----------------------------------------------------------------

	struct entry an_entry;
	char* restrict pathname = malloc(sizeof(an_entry.file));

	an_entry.uid = getuid();

	char procl[0xFFF];
	int fd = fileno(stream);
	sprintf(procl, "proc/self/fd/%d", fd);
    readlink(procl, pathname, 0xFFF);
	an_entry.time = time(NULL);

	fseek(stream,0L, SEEK_END);
	filesize = ftell(stream);
	fseek(stream, 0L, SEEK_SET);
	buf = malloc(filesize);
	fread(buf, filesize, 1, stream);
	md5_result = malloc(MD5_DIGEST_LENGTH);
	MD5(buf, filesize, md5_result);
	an_entry.fingerprint = md5_result;
	
	if(original_fwrite_ret == 0){
		an_entry.action_denied = 1;
	}
	an_entry.action_denied = 0; 

	an_entry.access_type = 2;


	if(eflag == 1){
		mpz_set_ui(plainchar,an_entry.uid);			//encrypt uid
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.uid = mpz_get_ui(cipherchar);

		mpz_set_ui(plainchar,an_entry.time);			//encrypt time and therefore date is also changed...
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.time = mpz_get_ui(cipherchar);

		mpz_set_ui(plainchar,an_entry.access_type);			//encrypt access type
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.access_type = mpz_get_ui(cipherchar);

		mpz_set_ui(plainchar,an_entry.action_denied);			//encrypt action denied flag
		mpz_powm(cipherchar, plainchar, e, n);
		an_entry.action_denied = mpz_get_ui(cipherchar);
	}

	log = fopen("./file_logging.log", "a");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
	}
	fprintf(log, "%ld\n",an_entry.uid);
	fprintf(log, "%s\n", pathname);
	fprintf(log, "%s",ctime(&an_entry.time));
	fprintf(log, "%lu\n",(unsigned long)an_entry.time);
	fprintf(log, "%ld\n",an_entry.access_type);
	fprintf(log, "%ld\n",an_entry.action_denied);
	fprintf(log, "%s\n\n",an_entry.fingerprint);
	fclose(log);

	return original_fwrite_ret;
}