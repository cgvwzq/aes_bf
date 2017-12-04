/* original source from: https://github.com/sebastien-riou/aes-brute-force */

#include "aes_ni.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <thread>
#include <string>
#include <vector>
#include <cmath>

#include <assert.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define PADDING 1

int hexdigit_value(char c)
{
	int nibble = -1;
	if (('0'<=c) && (c<='9'))
	{
		nibble = c-'0';
	}
	if (('a'<=c) && (c<='f'))
	{
		nibble = c-'a' + 10;
	}
	if (('A'<=c) && (c<='F'))
	{
		nibble = c-'A' + 10;
	}
	return nibble;
}

int is_hexdigit(char c) 
{
	return -1 != hexdigit_value(c);
}

size_t hexstr_to_bytes(uint8_t *dst, size_t dst_size, char *hexstr)
{
	unsigned int len = strlen(hexstr);
	if (dst_size > (len/2))
	{
		dst_size = (len/2);
	}
	memset (dst,0,dst_size);
	for (unsigned int i=0; i < dst_size*2; i++)
	{
		unsigned int shift = 4 - 4 * (i & 1);
		unsigned int charIndex = i; //len-1-i;
		char c = hexstr[charIndex];
		uint8_t nibble = hexdigit_value (c);
		dst[i/2] |= nibble << shift;
	}
	return dst_size;
}

void bytes_to_hexstr(char *dst,uint8_t *bytes, unsigned int nBytes)
{
	unsigned int i;
	for (i=0; i < nBytes; i++)
	{
		sprintf (dst+2*i,"%02X",bytes[i]);
	}
}

size_t cleanup_hexstr(char *hexstr, size_t hexstr_size, char *str, size_t str_size)
{
	size_t cnt=0;
	int lastIs0=0;
	for (unsigned int j=0; j < str_size; j++)
	{
		char c = str[j];
		if (is_hexdigit (c))
		{
			if (cnt == hexstr_size-1) // need final char for null
			{
				printf ("Too many hex digits. hexstr=%s\n", hexstr);
				hexstr[cnt] = 0;
				return -1;
			}
			hexstr[cnt++] = c;
		}
		else if (lastIs0)
		{
			if ('x' == c)
			{
				cnt--;
			}
			if('X'==c)
			{
				cnt--;
			}
		}
		lastIs0 = '0' == c;
	}
	hexstr[cnt] = 0;
	return cnt;
}

static
void print_bytes_sep(const char *msg,const unsigned char *buf, unsigned int size, const char m2[], const char sep[])
{
    unsigned int i;
    printf ("%s", msg);
    for (i=0; i < size-1; i++)
	{
		printf ("%02X%s", buf[i], sep);
	}
    if (i < size)
	{
		printf ("%02X", buf[i]);
	}
    printf ("%s", m2);
}

static
void print_128(const char m[], const uint8_t a[16], const char m2[])
{
	print_bytes_sep (m, a, 4, "_", "");
	print_bytes_sep ("", a+4 , 4, "_", "");
	print_bytes_sep ("", a+8 , 4, "_", "");
	print_bytes_sep ("", a+12, 4, m2, "");
}

static
void println_128(const char m[], const uint8_t a[16])
{
	print_128 (m, a, "\n");
}

size_t user_hexstr_to_bytes(uint8_t*out, size_t out_size, char *str, size_t str_size) 
{
    size_t hexstr_size = cleanup_hexstr (str, str_size,str,str_size);
    size_t conv_size = ((hexstr_size/2) < out_size) ? hexstr_size/2 : out_size;
	return hexstr_to_bytes (out,conv_size,str);
}

typedef struct u128 {
	uint8_t bytes[16];
} aes128_key_t;

typedef struct u128 aes128_block_t;

typedef struct voffset {
	uint8_t offsets[16];
	uint8_t n_offsets;
	uint8_t valid_chars[16][256];	
	uint8_t n_valid_chars;
	uint8_t next[16];
} voffset_t;

class aes_brute_force {

public:
	static bool done;
	static bool debug;

	static
	void reset()
	{
		done=false;
	}

	static
	bool is_done()
	{
		return done;
	}

	static
	void set_done()
	{
		done=true;
	}

    static
	void mask_to_offsets(uint8_t cipher_mask[16], uint8_t next_block[16], voffset_t *v)
	{
		v->n_offsets = 0;
		for (unsigned int i=0; i < 16; i++)
		{
			v->next[i] = next_block[i];
			if (cipher_mask[i]) 
			{
				v->offsets[v->n_offsets++] = i;
				uint8_t count = 0;
				for (unsigned int j=0x33; j < 0x7f; j++)
				{
					// generate range of valid chars for each byte
					if (j != 0x3b && j != 0x3d && j != 0x22)
					{
						v->valid_chars[i][count++] = j ^ v->next[i];
					}
				}
				v->n_valid_chars = count;
			}
		}
	}

	static
	bool is_valid_plaintext(uint8_t candidate[16], uint8_t plain_mask[16], uint8_t plain[16], uint8_t iv[16])
	{
		for (unsigned int i=0; i < 16; i++)
		{
			uint8_t c = candidate[i] ^ iv[i];
			// only ascii printable
			// if ((c & plain_mask[i]) ^ plain[i])
			if (c <= 0x1f || c >= 0x7f)
			{
				return false;	
			}
			// avoid problematic chars for cookie
			if (c == 0x3b || c == 0x3d || c == 0x22)
			{
				return false;
			}
		}
		return true;
	}

	static
	bool is_valid_plaintext_padding(uint8_t candidate[16], uint8_t plain_mask[16], uint8_t plain[16], uint8_t iv[16])
	{
		for (unsigned int i=0; i < 16; i++)
		{
			uint8_t c = candidate[i] ^ iv[i];
			// only ascii printable
			if (i < 15) // set to 15 for padding
			{
				// if ((c & plain_mask[i]) ^ plain[i])
				if (c <= 0x1f || c >= 0x7f)
				{
					return false;	
				}
				// avoid problematic chars for cookie
				if (c == 0x3b || c == 0x3d || c == 0x22)
				{
					return false;
				}
			}
			else if (c != 0x01)
			{
				return false;
			}
		}
		return true;
	}

	static
	void initial_ciphertext(uint8_t cipher[16], uint8_t next_block[16])
	{
		for (unsigned int i=0; i < 16; i++)
		{
			int seed = time(NULL);
			srand(seed);
			cipher[i] = (0x41 + (rand() % 57)) ^ next_block[i];	
		}
	}

	static
	void search(voffset_t v, uint8_t cipher[16], uint8_t key[16], uint8_t iv[16], uint8_t plain_mask[16], uint8_t plain[16], uint64_t &aes_cnt, bool &found)
	{
		uint8_t r[16];
		uint64_t n_loops = 1 << v.n_offsets; // iterate over all offsets combinations 
		found = false;
		__m128i key_schedule[20] = {0};
		aes128_load_key (key, key_schedule);
		aes_cnt = 0;

		for (uint64_t cnt=1; cnt < n_loops; cnt++)
		{
			// create index of offsets. more elegant with hamming weight and binary operations...
			uint8_t index[16] = {0}, ones = 0;
			for (uint8_t i=0; i < v.n_offsets; i++)
			{
				if (cnt & (1 << i))
				{
					index[ones++] = i;
				}
			}
			uint64_t n_chars = std::pow(v.n_valid_chars, ones);
			for (uint64_t c=0; c < n_chars; c++)
			{
				uint64_t t = c;
				for (uint8_t o=0; o < ones; o++)
				{
					cipher[v.offsets[index[o]]] = v.valid_chars[index[o]][t % v.n_valid_chars];
					t = t / v.n_valid_chars;
					
				}
				aes128_dec (key_schedule, cipher, r);
				#ifndef PADDING
					if (is_valid_plaintext (r, plain_mask, plain, iv))
				#else
					if (is_valid_plaintext_padding (r, plain_mask, plain, iv))
				#endif
				{
					found = true;
					done = true;
					return;
				}
				aes_cnt++;
				if (debug && !((aes_cnt+1) % 300000000))
				{
					println_128 ("\t(debug): ", cipher);
				}
			}
		}
	}

	explicit aes_brute_force(uint8_t cipher_mask[16], uint8_t cipher[16], uint8_t key[16], uint8_t iv[16], uint8_t plain_mask[16], uint8_t plain[16], uint8_t next_block[16])
	{
		aes128_block_t b;

		memcpy (&b, cipher, 16);
		memcpy (this->cipher_mask, cipher_mask, 16);
		memcpy (this->key, key, 16);
		memcpy (this->iv, iv, 16);
		memcpy (this->plain_mask, plain_mask, 16);
		memcpy (this->plain, plain, 16);
		memcpy (this->next_block, next_block, 16);

		blocks.push_back (b);
		mask_to_offsets (cipher_mask, next_block, &this->v);
		nbits = this->v.n_offsets * 8;
	}

	void compute()
	{
		loop_cnt = 0;
		for(auto b=blocks.begin(); b != blocks.end(); ++b) 
		{
			uint64_t cnt;
			search (v, b->bytes, key, iv, plain_mask, plain, cnt, found);
			loop_cnt += cnt;
			if (found)
			{
				memcpy (valid_cipher, b->bytes, 16);
				return;
			}
			if (is_done()) // used for multithread operations
			{ 
				return;
			}
		}
    }

	void operator()()
	{
      compute ();
    }

	void push(uint8_t block[16])
	{
		aes128_block_t b;
		memcpy (&b, block, 16);
		blocks.push_back (b);
	}

	// properties
	uint64_t loop_cnt;
	bool found;
	voffset_t v;
	unsigned int nbits;
	uint8_t valid_cipher[16];
	std::vector<aes128_block_t> blocks;
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t plain[16];
	uint8_t plain_mask[16];
	uint8_t cipher[16];
	uint8_t cipher_mask[16];
	uint8_t next_block[16];
};

bool aes_brute_force::done = false;
bool aes_brute_force::debug = true;

int main (int argc, char*argv[]) 
{
	uint8_t payload[16] = {0};
	uint8_t key[16] = {0};
	uint8_t iv[16] = {0};
	uint8_t plain_mask[16] = {0};
	uint8_t plain[16] = {0};
	uint8_t next_block[16] = {0};
	uint8_t cipher_mask[16] = {0};
	uint8_t cipher[16] = {0};

	const char *payload_str = "4D346731_435F6330_306B3133_5F465457"; // payload

	const char *key_str = "FD621FE5_A2B40253_9DFA147C_A9272778"; //  fixed on Linux 

	#ifndef PADDING
		const char *iv_str = "20202020_20202020_20202020_20202020"; // fixed on Chrome
		const char *plain_mask_str = "A0A0A0A0_A0A0A0A0_A0A0A0A0_A0A0A0A0A0"; // bit mask for valid chars
		const char *plain_str = "20202020_20202020_20202020_20202020"; // valid ascii chars
	#else
		const char *iv_str = "7B007D00_2A007B00_2D002D00_3A002800";
		const char *plain_mask_str = "A0A0A0A0_A0A0A0A0_A0A0A0A0_A0A0A0A0FF"; // bit mask for valid chars + padding
		const char *plain_str = "20202020_20202020_20202020_20202001"; // valid ascii chars + padding
	#endif

	const char *cipher_mask_str = "FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF"; // try all chars
	const char *cipher_str = "00000000_00000000_00000000_00000000"; 
	const char *next_block_str = "00000000_00000000_00000000_00000000"; 

	char buf[8][1024] = {0};

	memcpy (buf[0], payload_str, MIN(strlen (payload_str), 1024));
	memcpy (buf[1], key_str, MIN(strlen (key_str), 1024));
	memcpy (buf[2], iv_str, MIN(strlen (iv_str), 1024));
	memcpy (buf[3], plain_mask_str, MIN(strlen (plain_mask_str), 1024));
	memcpy (buf[4], plain_str, MIN(strlen (plain_str), 1024));
	memcpy (buf[5], next_block_str, MIN(strlen (next_block_str), 1024));
	memcpy (buf[6], cipher_mask_str, MIN(strlen (cipher_mask_str), 1024));
	memcpy (buf[7], cipher_str, MIN(strlen (cipher_str), 1024));

	if (0 != aes128_self_test())
	{
		std::cerr << "ERROR: AES-NI self test failed" << std::endl;
		exit(-1);
    }

    unsigned int len;
    len = user_hexstr_to_bytes (payload, 16, buf[0], strlen (buf[0]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (key, 16, buf[1], strlen (buf[1]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (iv, 16, buf[2], strlen (buf[2]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (plain_mask, 16, buf[3], strlen (buf[3]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (plain, 16, buf[4], strlen (buf[4]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (next_block, 16, buf[5], strlen (buf[5]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (cipher_mask, 16, buf[6], strlen (buf[6]) + 1);
	assert (16 == len);
    len = user_hexstr_to_bytes (cipher, 16, buf[7], strlen (buf[7]) + 1);
	assert (16 == len);

	__m128i key_schedule[20] = {0};
	aes128_load_key (key, key_schedule);
	#ifndef PADDING
		aes128_dec (key_schedule, payload, next_block); 
	#endif

	unsigned int n_threads = std::thread::hardware_concurrency ();
	//if (0 == n_threads)
	if (true) // debug
	{
		n_threads = 1;
	}

	std::cout << "[+] INFO: " << n_threads << " concurrent threads supported in hardware." << std::endl << std::endl;
	std::cout << "[+] Search parameters:\t" << std::endl << std::endl;
	std::cout << "\t- n_threads:\t" << n_threads << std::endl;
	println_128 ("\t- payload:\t", payload);
	println_128 ("\t- key:\t\t", key);
	println_128 ("\t- iv:\t\t", iv);
    println_128 ("\t- plain_mask:\t", plain_mask);
    println_128 ("\t- plain:\t", plain);
	#ifndef PADDING
		// start from valid ciphertext
		aes_brute_force::initial_ciphertext (cipher, next_block);
	#endif
    println_128 ("\t- cipher:\t", cipher);
    println_128 ("\t- next_block:\t", next_block);
	std::cout << std::endl;

	std::cout << "[+] Dividing work in jobs..." << std::endl << std::endl;
	voffset_t v;
	aes_brute_force::mask_to_offsets (cipher_mask, next_block, &v);
	uint8_t jobs_cipher_mask[16];
	memcpy (jobs_cipher_mask, cipher_mask, 16);

	if (1 == v.n_offsets)
	{
		n_threads = 1;
		std::cout << "[+] INFO: n_threads set to 1 because n_offsets=1" << std::endl;
	}
	if (1 != n_threads)
	{
		jobs_cipher_mask[v.offsets[0]] = 0; //fix this key byte at the job level.
	}
	std::vector<std::thread *> threads (n_threads);
	std::vector<aes_brute_force *> jobs (n_threads);
	aes_brute_force::reset ();

	int n_ciphers_per_thread = (n_threads == 1) ? 0 : ((v.n_valid_chars + n_threads - 1) / n_threads);
	unsigned int nbits = 0;
	for (unsigned int i=v.n_valid_chars; i; i = i >> 1, nbits++);

	unsigned int jobs_cnt = 0;
	for (unsigned int thread_i=0; thread_i < n_threads; thread_i++)
	{
		cipher[v.offsets[0]] = v.valid_chars[0][jobs_cnt++];
		jobs.at(thread_i) = new aes_brute_force (jobs_cipher_mask, cipher, key, iv, plain_mask, plain, next_block);
		printf ("\tthread_%d: %d jobs ", thread_i, n_ciphers_per_thread);
		print_128 ("(mask : ", jobs_cipher_mask, ")\n");
		for (int i=0; i < n_ciphers_per_thread-1; i++)
		{
			cipher[v.offsets[0]] = v.valid_chars[0][jobs_cnt++];
			jobs.at(thread_i)->push(cipher);
		}
	}
	// TODO: calculate entropy from given masks
	std::cout  << std::endl << "\tlaunching " << (v.n_offsets * nbits) << " bits search" << std::endl;
	std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::now();
	for (unsigned int thread_i=0; thread_i < n_threads; thread_i++)
	{
		threads.at(thread_i) = new std::thread(&aes_brute_force::compute, jobs.at(thread_i));
	}

	bool found = false;
	uint64_t loop_cnt = 0;
	int winner = -1;
	for (unsigned int thread_i=0; thread_i < n_threads; thread_i++)
	{
		threads.at(thread_i)->join();
		if (jobs.at(thread_i)->found)
		{
			found = true;
			winner = thread_i;
			memcpy (cipher, jobs.at(thread_i)->valid_cipher, 16);

		}
		loop_cnt += jobs.at(thread_i)->loop_cnt;
	}
	std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();
	std::cout << std::endl;
	if (found)
	{
		std::cout << "[+] Thread " << winner << " claims to have found a valid ciphertext" << std::endl;
        println_128 ("[+] CIPHER FOUND: ", cipher);
    }
	else
	{
        std::cout << "[!] No valid cipher could be found." << std::endl;
    }
	std::cout << std::endl << "[+] Performances:" << std::endl;
    std::cout << "\t" << std::dec << loop_cnt << " AES128 operations done in ";
    std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1);
    std::cout << time_span.count() << "s" << std::endl;

	if (!loop_cnt)
	{
		return 1;
	}

    uint64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1).count();
    unsigned int aes_op_duration_ns = ns / loop_cnt;

    std::cout << "\t" << aes_op_duration_ns << " ns per AES128 operation" <<std::endl;
    uint64_t ciphers_per_sec = loop_cnt / time_span.count();
	if (ciphers_per_sec > 1000000)
	{
		std::cout << "\t" << std::fixed << std::setprecision(2) << ciphers_per_sec/1000000.0 << " million ciphers per second" << std::endl;
	}
	else
	{
		std::cout << "\t" << ciphers_per_sec << " cipers per second" << std::endl;
	}
	if (found)
	{
		uint8_t dec[16] = {0};
		char txt[17] = {0}; 
		__m128i key_schedule[20] = {0};
		aes128_load_key (key, key_schedule);
		aes128_dec (key_schedule, cipher, dec); 
		for (unsigned int i=0; i < 16; i++) {
			dec[i] ^= iv[i]; // IV
		}
		memcpy (txt, dec, 16);
		println_128 ("[+] Ciphertext: ", cipher);
		println_128 ("[+] Plaintext: ", dec);
		printf("\tascii: %s (length=%zu)\n", txt, strlen(txt));
		#ifndef PADDING
			char txt2[17] = {0};
			println_128 ("[+] Next block: ", next_block);
			for (unsigned int i=0; i < 16; i++) {
				next_block[i] ^= cipher[i]; 
			}
			memcpy (txt2, next_block, 16);
			println_128 ("[+] Next block XOR cipher: ", next_block);
			printf("\tascii: %s (length=%zu)\n", txt2, strlen(txt2));
		#endif
	}

    return 0;
}
