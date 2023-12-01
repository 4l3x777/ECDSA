#include <crypto_pseudo_random_generator.h>
#include <aes.h>

#include <chrono>
#include <random>
#include <vector>

std::shared_ptr<std::vector<uint8_t>> CryptoPseudoRandomGenerator::generate(uint64_t qwPRNSize)
{
	// Create AES_256 Instance and Set it in OFB mode
	AES_256 aes256Instance;
	aes256Instance.SetEncryptionMode(2);

	union FormattedGeneratorNumbers
	{
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatData;

	// Get current time in nanoseconds to mt19937_64 Seed
	auto current_time_now = std::chrono::high_resolution_clock::now();
	std::mt19937_64 urandom_generator;
	// Set Seed
	urandom_generator.seed(current_time_now.time_since_epoch().count());

	// Generate PRN = Key = 32 byte (256 bit)
	std::shared_ptr<std::vector<uint8_t>> arrbyKey = std::make_shared<std::vector<uint8_t>>();
	FormatData.qwArray[0] = urandom_generator();
	FormatData.qwArray[1] = urandom_generator();
	for (uint8_t i : FormatData.byArray)
	{
		arrbyKey->push_back(i);
	}
	FormatData.qwArray[0] = urandom_generator();
	FormatData.qwArray[1] = urandom_generator();
	for (uint8_t i : FormatData.byArray)
	{
		arrbyKey->push_back(i);
	}

	// Generate PlainText from mt19937_64 generator
	std::shared_ptr<std::vector<uint8_t>> arrbyPlainText = std::make_shared<std::vector<uint8_t>>();
	for (uint64_t dwCurrentBlock = 0; dwCurrentBlock < qwPRNSize / 16; dwCurrentBlock++)
	{
		FormatData.qwArray[0] = urandom_generator();
		FormatData.qwArray[1] = urandom_generator();
		for (uint8_t i : FormatData.byArray)
		{
			arrbyPlainText->push_back(i);
		}
	}

	// If qwPRNSize % 16 != 0 add qwPRNSize bytes in arrbyPlainText
	if (qwPRNSize % 16 != 0)
	{
		FormatData.qwArray[0] = urandom_generator();
		FormatData.qwArray[1] = urandom_generator();
		for (uint8_t i = 0; i < qwPRNSize % 16; i++)
		{
			arrbyPlainText->push_back(FormatData.byArray[i]);
		}
	}

	std::shared_ptr<std::vector<uint8_t>> arrbyPRN = aes256Instance.Encrypt(arrbyPlainText, arrbyKey);

	// Delete unnecessary bytes
	while (arrbyPRN->size() != qwPRNSize)
	{
		arrbyPRN->pop_back();
	}

	return arrbyPRN;
};
