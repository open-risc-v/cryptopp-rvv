/* cryptopp 探针：SHA-256 与 AES 的 CTR/CBC 确定性路径，输出 FNV 哈希。
   计时写 stderr（best-of-reps），stdout 只放可比哈希。
   AES 覆盖 128/192/256 三种密钥长度 × CTR/CBC 两种模式。 */
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

/* CTR 与 CBC 各跑一次，返回哈希对应的输出缓冲 */
template <int KEYLEN>
static void run_ctr(const CryptoPP::byte *in, size_t n, const CryptoPP::byte *iv,
                    std::vector<CryptoPP::byte> &out, double &ms, int reps)
{
	std::vector<CryptoPP::byte> key(KEYLEN);
	for (int i = 0; i < KEYLEN; i++) key[i] = (CryptoPP::byte)(0x40 + i);

	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key.data(), key.size(), iv);
	enc.ProcessData(out.data(), in, n);

	ms = 1e18;
	std::vector<CryptoPP::byte> tmp(n);
	for (int r = 0; r < reps; r++) {
		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e2;
		e2.SetKeyWithIV(key.data(), key.size(), iv);
		double t0 = now_ms();
		e2.ProcessData(tmp.data(), in, n);
		double t1 = now_ms();
		if (t1 - t0 < ms) ms = t1 - t0;
	}
}

template <int KEYLEN>
static void run_cbc(const CryptoPP::byte *in, size_t n, const CryptoPP::byte *iv,
                    std::vector<CryptoPP::byte> &out, double &ms, int reps)
{
	std::vector<CryptoPP::byte> key(KEYLEN);
	for (int i = 0; i < KEYLEN; i++) key[i] = (CryptoPP::byte)(0x40 + i);

	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key.data(), key.size(), iv);
	enc.ProcessData(out.data(), in, n);

	ms = 1e18;
	std::vector<CryptoPP::byte> tmp(n);
	for (int r = 0; r < reps; r++) {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e2;
		e2.SetKeyWithIV(key.data(), key.size(), iv);
		double t0 = now_ms();
		e2.ProcessData(tmp.data(), in, n);
		double t1 = now_ms();
		if (t1 - t0 < ms) ms = t1 - t0;
	}
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

	CryptoPP::byte iv[16];
	for (int i = 0; i < 16; i++) iv[i] = (CryptoPP::byte)(0x10 + i);

	std::vector<CryptoPP::byte> out(in.size());
	double bctr256, bcbc256, bctr128, bcbc128, bctr192, bcbc192;

	run_ctr<32>(in.data(), in.size(), iv, out, bctr256, reps);
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aes256ctr n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	run_cbc<32>(in.data(), in.size(), iv, out, bcbc256, reps);
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aes256cbc n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	run_ctr<16>(in.data(), in.size(), iv, out, bctr128, reps);
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aes128ctr n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	run_cbc<16>(in.data(), in.size(), iv, out, bcbc128, reps);
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aes128cbc n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	run_ctr<24>(in.data(), in.size(), iv, out, bctr192, reps);
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aes192ctr n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	run_cbc<24>(in.data(), in.size(), iv, out, bcbc192, reps);
	std::fwrite(out.data(), 1, out.size(), f);
	std::printf("aes192cbc n=%zu fnv=%016llx\n", out.size(), fnv1a(out.data(), out.size()));

	double bsha = 1e18;
	{
		CryptoPP::byte d2[CryptoPP::SHA256::DIGESTSIZE];
		for (int r = 0; r < reps; r++) {
			double t0 = now_ms();
			CryptoPP::SHA256().CalculateDigest(d2, in.data(), in.size());
			double t1 = now_ms();
			if (t1 - t0 < bsha) bsha = t1 - t0;
		}
	}

	std::fprintf(stderr,
		"sha256_ms=%.3f aes256ctr_ms=%.3f aes256cbc_ms=%.3f aes128ctr_ms=%.3f "
		"aes128cbc_ms=%.3f aes192ctr_ms=%.3f aes192cbc_ms=%.3f\n",
		bsha, bctr256, bcbc256, bctr128, bcbc128, bctr192, bcbc192);

	std::fclose(f);
	return 0;
}
