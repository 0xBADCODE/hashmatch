// gcc hashmatch.c -o hashmatch -lcrypto -fopenmp -lpthread
// ./hashmatch md5 `perl -e 'print("\x01\x01\x01\x01")'`
/* Xeon 2014 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pthread.h>

#define NUM_THREADS 4

/* multithreading */

int check_hash(unsigned char *hash, char *word)
{
/*------TESTING-----------------------------------------------------*/
//	char test[] = {0x22, 0x39}; //MD5
//	int ret = memcmp(hash, test, 2);
//	printf("\nHASH %s\nTEST %s\nVALUE %d\n\n", hash, test, ret);
/*------------------------------------------------------------------*/

	if(!memcmp(hash, word, strlen(word))){
		return 1;
	}
        return 0;
}

void output_hash(unsigned char *hash, char *algo)
{
	int i;
	if(!strncmp(algo, "md5", 3)){
		for (i = 0; i < 16; i++) {
			printf("%02x ", hash[i]);
		}
	}
	else if(!strncmp(algo, "sha1", 3)
		|| !strncmp(algo, "rmd160", 6)){
		for (i = 0; i < 20; i++) {
			printf("%02x ", hash[i]);
		}
	}
	if(!strncmp(algo, "sha256", 6)){
		for (i = 0; i < 32; i++) {
			printf("%02x ", hash[i]);
		}
	}
	if(!strncmp(algo, "sha384", 6)){
		for (i = 0; i < 48; i++) {
			if(i % 24 == 0) printf("\n");
			printf("%02x ", hash[i]);
		}
	}
	if(!strncmp(algo, "sha512", 6)){
		for (i = 0; i < 64; i++) {
			if(i % 32 == 0) printf("\n");
			printf("%02x ", hash[i]);
		}
	}
	printf("\n");
}

int do_hash(char *algo, char *word)
{
	unsigned char hash[64 + 1], seed[10];
	double tm;
	int iterations = 0;
	clock_t cstart = clock(), cend = 0;

	srandom(time(NULL));
	memset(&hash, 0, sizeof hash);

	unsigned long r[NUM_THREADS] = {0};
	pthread_t thread[NUM_THREADS];

	int i;
	for(i = 0; i < NUM_THREADS; i++){
		r[i] = random()^i;
//		printf("Thread number %d, r = %lu, ", i, r[i]); //DEBUG
//		printf("created at 0x%08lx\n", (unsigned long) &thread[i]); //DEBUG
	}
//	return 0; //DEBUG

	if(!strncmp(algo, "md5", 3)){
		for(;;){
			iterations++;
			sprintf(seed, "%lu", random());
			MD5(seed, sizeof seed, hash);
			//output_hash(hash, algo); //DEBUG
			if(check_hash(hash, word))
				break;
		}
	}
	else if(!strncmp(algo, "sha1", 4)){
		for(;;){
			iterations++;
			sprintf(seed, "%lu", random());
			SHA1(seed, sizeof seed, hash);
			//output_hash(hash, algo); //DEBUG
			if(check_hash(hash, word)){
				break;
			}
		}
	}
	else if(!strncmp(algo, "sha256", 6)){
		for(;;){
			iterations++;
			sprintf(seed, "%lu", random());
			SHA256(seed, sizeof seed, hash);
			//output_hash(hash, algo); //DEBUG
			if(check_hash(hash, word)){
				break;
			}
		}
	}
	else if(!strncmp(algo, "sha384", 6)){
		for(;;){
			iterations++;
			sprintf(seed, "%lu", random());
			SHA384(seed, sizeof seed, hash);
			//output_hash(hash, algo); //DEBUG
			if(check_hash(hash, word)){
				break;
			}
		}
	}
	else if(!strncmp(algo, "sha512", 6)){
		for(;;){
			iterations++;
			sprintf(seed, "%lu", random());
			SHA512(seed, sizeof seed, hash);
			//output_hash(hash, algo); //DEBUG
			if(check_hash(hash, word)){
				break;
			}
		}
	}
	else if(!strncmp(algo, "rmd160", 6)){
		for(;;){
			iterations++;
			sprintf(seed, "%lu", random());
			RIPEMD160(seed, sizeof seed, hash);
			//output_hash(hash, algo); //DEBUG
			if(check_hash(hash, word)){
				break;
			}
		}
	}
	else {
		printf("Unknown hashing algorithm.\n\n");
		return 1;
	}

	cend = clock();
        tm = ((double)cend - (double)cstart) * 1.0e-6;

	printf("String match found in %.3f seconds. (%d iterations)\nHASH: ", tm, iterations);
	output_hash(hash, algo);
	printf("SEED: %s\n\n", seed);
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 3) { // arg check
		fprintf(stderr, "Usage: %s <algorithm> <word>\n", argv[0]);
		printf("Supported algorithms [MD5|SHA1|SHA256|SHA384|SHA512|RMD160]\n\n");
		return 1;
	}

	char algo[8 + 1], word[64 + 1];
	memset(&algo, 0, sizeof algo);
	memset(&word, 0, sizeof word);

	int i;
	for(i = 0; i < strlen(argv[1]); i++){
		algo[i] = tolower(argv[1][i]);
	}
	strncpy(word, argv[2], strlen(argv[2]));

	printf("\nMatching string [%s] to beginning of [%s] hash...\n\n", word, algo);
	do_hash(algo, word);
	return 1;
}
