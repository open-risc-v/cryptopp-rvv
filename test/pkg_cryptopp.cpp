/* cryptopp 探针：SHA-256 与 AES-256-CTR 两条确定性路径，输出 FNV 哈希。 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
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

int main(int argc, char **argv)
{
	if (argc < 2) { std::fprintf(stderr, "usage: %s <out.bin>\n", argv[0]); return 2; }
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

	std::fclose(f);
	return 0;
}
