#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <openssl/sha.h>

#define FAILIF(x, msg...) do {        \
	if ((x)) {                    \
		fprintf(stderr, msg); \
		_exit(1);             \
	}                             \
} while(0)

static void help(const char *prog, int err) {
	printf("%s: [-c <chunk-size-in-bytes>] [-z] [-f] <list-of-files>\n"     \
	       "    break up every file in the provided list into chunks and\n" \
	       "    print each chunk's SHA1 hash, the file it came from, and\n" \
	       "    its file offset, while potentially ignoring those chunks\n" \
	       "    that are all zeroes.\n\n"                                   \
	       "    -q                       quiet (only print SHAs)\n"         \
	       "    -c <chunk-size>          defaults to 512\n"                 \
	       "    <list-of-files>          must not be empty\n",
	       prog);
	_exit(err);
}

static void process(const char *name,
		    void *chunk, size_t chunk_sz,
		    const unsigned char *ignore,
		    int quiet);


int main (int argc, char **argv)
{
	char **files;
	size_t chunk_sz = 512;
	void *chunk;
	unsigned char *ignore = NULL, ignore_sha[SHA_DIGEST_LENGTH];
	int quiet = 1;

	int opt;
	do {
		opt = getopt(argc, argv, "c:zhq");
		switch (opt) {
			case 'c':
				FAILIF(1 != sscanf(optarg, "%lu", &chunk_sz), "Invalid chunk-size string\n");
				FAILIF(chunk_sz & (chunk_sz - 1), "Chunk size is not a power of two!\n");
				break;
			case 'z':
				ignore = ignore_sha;
				break;
			case 'q':
				quiet = 0;
				break;
			case '?':
				/* fall through */
			case 'h':
				help(*argv, opt == '?');
				break;
			default:
				break;
		}
	} while (opt != -1);

	FAILIF(optind >= argc, "Expecting file name(s)!\n");

	files = argv + optind;
	chunk = malloc(chunk_sz);
	FAILIF(!chunk, "Could not allocate chunk of size %lu\n", chunk_sz);

	if (ignore) {
		memset(chunk, 0, chunk_sz);
		SHA1(chunk, chunk_sz, ignore);
	}

	while (*files) {
		process(*files, chunk, chunk_sz, ignore, quiet);
		files++;
	}

	return 0;
}

static void process(const char *name,
		    void *chunk, size_t chunk_sz,
		    const unsigned char *ignore,
		    int quiet)
{
	int fd;
	int rc;
	unsigned char sha[SHA_DIGEST_LENGTH];
	struct stat st;
	size_t num_chunks;
	size_t i;

	fd = open (name, O_RDONLY);
	FAILIF(fd < 0, "Could not open [%s]: %s\n", name, strerror(errno));

	rc = fstat(fd, &st);
	FAILIF(rc < 0, "Could not fstat [%s]: %s\n", name, strerror(errno));

	i = 0;
	num_chunks = st.st_size / chunk_sz;
	while (1) {
		rc = read(fd, chunk, chunk_sz);
		if (!rc)
			break;
		if (rc < 0) {
			FAILIF(errno != EINTR,
			       "Could not read from [%s]: %s\n",
			       name, strerror(errno));
			continue;
		}

		FAILIF(rc < chunk_sz && num_chunks > 1 && i < num_chunks - 1,
		       "Unexpected chunk size %u for chunk %lu (out of %lu) of file [%s]!\n",
		       rc, i, num_chunks, name);

		SHA1(chunk, rc, sha);

		if (ignore && !memcmp(ignore, sha, sizeof(sha))) {
			i++;
			continue;
		}

		if (quiet)
			printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"\
			       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x %8ld %s\n",
			       sha[ 0], sha[ 1], sha[ 2], sha[ 3], sha[ 4],
			       sha[ 5], sha[ 6], sha[ 7], sha[ 8], sha[ 9],
			       sha[10], sha[11], sha[12], sha[13], sha[14],
			       sha[15], sha[16], sha[17], sha[18], sha[19],
			       i * chunk_sz, name);
		else
			printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"\
			       "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			       sha[ 0], sha[ 1], sha[ 2], sha[ 3], sha[ 4],
			       sha[ 5], sha[ 6], sha[ 7], sha[ 8], sha[ 9],
			       sha[10], sha[11], sha[12], sha[13], sha[14],
			       sha[15], sha[16], sha[17], sha[18], sha[19]);

		i++;
	}

	close (fd);
}
