/* cryptopp 探针：SHA-256 与 AES-256-CTR 两条确定性路径，输出 FNV 哈希。
   计时写 stderr（best-of-reps），stdout 只放可比哈希。 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <time.h>
#include "sha.h"
#include "aes.h"
#include "modes.h"
#include "filters.h"

static unsigned long long fnv1a(const void *buf, size_t n)
{
	const unsigned char *p = (const unsigned char *)buf;
	unsigned long long h = 0xcbf29ce484222325ULL;
	for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
	return h;
}

static double now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
	if (argc < 2) { std::fprintf(stderr, "usage: %s <out.bin> [reps]\n", argv[0]); return 2; }
	int reps = argc > 2 ? std::atoi(argv[2]) : 1;
	if (reps < 1) reps = 1;
	FILE *f = std::fopen(argv[1], "wb");
	if (!f) { std::perror("fopen"); return 2; }

	std::vector<CryptoPP::byte> in(65536);
	for (size_t i = 0; i < in.size(); i++) in[i] = (CryptoPP::byte)((i * 31 + i / 7) & 0xff);

	CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256().CalculateDigest(digest, in.data(), in.size());
	std::fwrite(digest, 1, sizeof(digest), f);
	std::printf("sha256 fnv=%016llx\n", fnv1a(digest, sizeof(digest)));

	CryptoPP::byte key[32], iv[16];
	for (int i = 0; i < 32; i++) key[i] = (CryptoPP::byte)(0x40 + i);
	for (int i = 0; i < 16; i++) iv[i] = (CryptoPP::byte)(0x10 + i);

	std::vector<CryptoPP::byte> out(in.size());
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), iv);
	enc.ProcessData(out.data(), in.data(), in.size());
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aesctr n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	// 计时：SHA-256 与 AES-256-CTR，各 best-of-reps
	double bsha = 1e18, bctr = 1e18;
	std::vector<CryptoPP::byte> tmp(in.size());
	for (int r = 0; r < reps; r++) {
		double t0 = now_ms();
		CryptoPP::SHA256().CalculateDigest(digest, in.data(), in.size());
		double t1 = now_ms();
		if (t1 - t0 < bsha) bsha = t1 - t0;

		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e2;
		e2.SetKeyWithIV(key, sizeof(key), iv);
		t0 = now_ms();
		e2.ProcessData(tmp.data(), in.data(), in.size());
		t1 = now_ms();
		if (t1 - t0 < bctr) bctr = t1 - t0;
	}
	std::fprintf(stderr, "sha256_ms=%.3f aesctr_ms=%.3f\n", bsha, bctr);

	std::fclose(f);
	return 0;
}
