#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/sha.h>

#define FAILIF(x, msg...) do {        \
	if ((x)) {                    \
		fprintf(stderr, msg); \
		_exit(1);             \
	}                             \
} while(0)

static void help(const char *prog, int err) {
	printf("%s: [-c <chunk-size-in-bytes>] [-z] <list-of-files>\n"          \
	       "    break up every file in the provided list into chunks and\n" \
	       "    print each chunk's SHA1 hash, the file it came from, and\n" \
	       "    its file offset, while potentially ignoring those chunks\n" \
	       "    that are all zeroes.\n\n"                                   \
	       "    <chunk-size-in-bytes> defaults to 512\n"                    \
	       "    <list-of-files>       must not be empty\n",
	       prog);
	_exit(err);
}

static void process(const char *name);

int main (int argc, char **argv)
{
	int chunk = 512;
	int ignore_zero_chunks = 0;
	char **files;

	int opt;
	do {
		opt = getopt(argc, argv, "c:zh");
		switch (opt) {
			case 'c':
				printf("chunk size [%s]\n", optarg);
				FAILIF(1 != sscanf(optarg, "%u", &chunk), "Invalid chunk-size string\n");
				FAILIF(chunk & (chunk - 1), "Chunk size is not a power of two!\n");
				break;
			case 'z':
				printf("ignoring zero-sized chunks\n");
				ignore_zero_chunks = 1;
				break;
			case '?':
				fprintf(stderr, "unknown command-line option %c\n", optopt);
				// fall through
			case 'h':
				help(*argv, opt == '?');
				break;
			default:
				break;
		}
	} while (opt != -1);

	FAILIF(optind >= argc, "Expecting file name(s)!\n");

	files = argv + optind;
	while (*files) {
		process(*files);
		files++;
	}

	return 0;
}


static void process(const char *name)
{
	printf("file [%s]\n", name);
}
