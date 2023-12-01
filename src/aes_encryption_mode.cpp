#include <aes_encryption_mode.h>
#include <thread_pool.h>
#include <random>
#include <chrono>

/*Start InterfaceEncryptionMode Methods Realization*/
void IEncryptionMode::AdditionBlocksRatio(std::shared_ptr<std::vector<uint8_t>> arrbyBufferPublicText)
{
	// Work by GOST 34.13-2015
	arrbyBufferPublicText->push_back(0x80);
	for (uint8_t i = 0; i < (arrbyBufferPublicText->size() % 16); i++)
	{
		arrbyBufferPublicText->push_back(0x00);
	}
}
/*End InterfaceEncryptionMode Methods Realization*/

/*Start ECB Methods Realization*/
std::shared_ptr<std::vector<uint8_t>> ECB::Encryption(std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	// Check AdditionBlockRatio
	if (byarrBufferPlainText->size() % 16 != 0)
	{
		AdditionBlocksRatio(byarrBufferPlainText);
	}

	// number of 16 bytes blocks
	uint64_t qwSizePlainTextBlocks = byarrBufferPlainText->size() / 16;

	// encrypt blocks
	using thread_result = std::future<std::vector<uint8_t>>;
	auto thread_pool = std::make_shared<progschj::ThreadPool>(std::thread::hardware_concurrency());
	auto jobs_count = qwSizePlainTextBlocks;
	std::vector<thread_result> thread_jobs(jobs_count);
	for (std::size_t qwCurrentBlock = 0; qwCurrentBlock < jobs_count; ++qwCurrentBlock)
	{
		auto thread_job = [this, &byarrBufferPlainText, &byarrKey, qwCurrentBlock]()
		{
			return _pRijndael->Encrypt(std::vector<uint8_t>(byarrBufferPlainText->begin() + qwCurrentBlock * 16, byarrBufferPlainText->begin() + (qwCurrentBlock + 1) * 16), byarrKey);
		};
		thread_jobs[qwCurrentBlock] = thread_pool->enqueue(thread_job);
	}

	auto result = std::make_shared<std::vector<uint8_t>>();
	for (thread_result &job_result : thread_jobs)
	{
		auto res = job_result.get();
		result->insert(result->end(), res.begin(), res.end());
	}

	return result;
}

std::shared_ptr<std::vector<uint8_t>> ECB::Decryption(std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	// number of 16 bytes blocks
	uint64_t qwSizeCipherTextBlocks = byarrBufferCipherText->size() / 16;

	// decrypt blocks
	using thread_result = std::future<std::vector<uint8_t>>;
	auto thread_pool = std::make_shared<progschj::ThreadPool>(std::thread::hardware_concurrency());
	auto jobs_count = qwSizeCipherTextBlocks;
	std::vector<thread_result> thread_jobs(jobs_count);
	for (std::size_t qwCurrentBlock = 0; qwCurrentBlock < jobs_count; ++qwCurrentBlock)
	{
		auto thread_job = [this, &byarrBufferCipherText, &byarrKey, qwCurrentBlock]()
		{
			return _pRijndael->Decrypt(std::vector<uint8_t>(byarrBufferCipherText->begin() + qwCurrentBlock * 16, byarrBufferCipherText->begin() + (qwCurrentBlock + 1) * 16), byarrKey);
		};
		thread_jobs[qwCurrentBlock] = thread_pool->enqueue(thread_job);
	}

	auto result = std::make_shared<std::vector<uint8_t>>();
	for (thread_result &job_result : thread_jobs)
	{
		auto res = job_result.get();
		result->insert(result->end(), res.begin(), res.end());
	}

	return result;
}
/*End ECB Methods Realization*/

/*Start CTR Methods Realization*/
std::shared_ptr<std::vector<uint8_t>> CTR::Encryption(std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	union FormattedGeneratorNumbers
	{
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	// Get current time in nanoseconds to mt19937_64 Seed
	auto current_time_now = std::chrono::high_resolution_clock::now();
	std::mt19937_64 urandom_generator;
	// Set Seed
	urandom_generator.seed(current_time_now.time_since_epoch().count());

	// Generate IV
	FormatIV.qwArray[0] = urandom_generator();
	FormatIV.qwArray[1] = urandom_generator();

	// Write IV, Where IV = Counter
	std::shared_ptr<std::vector<uint8_t>> IV = std::make_shared<std::vector<uint8_t>>();
	for (uint8_t i : FormatIV.byArray)
	{
		IV->push_back(i);
	}

	// Output Buffer
	std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText = std::make_shared<std::vector<uint8_t>>();

	// Insert IV in BufferCipherText
	byarrBufferCipherText->insert(byarrBufferCipherText->end(), IV->begin(), IV->end());

	// Check AdditionBlockRatio
	if (byarrBufferPlainText->size() % 16 != 0)
	{
		AdditionBlocksRatio(byarrBufferPlainText);
	}

	uint64_t qwSizePlainTextBlocks = byarrBufferPlainText->size() / 16;

	// encrypt blocks
	using thread_result = std::future<std::vector<uint8_t>>;
	auto thread_pool = std::make_shared<progschj::ThreadPool>(std::thread::hardware_concurrency());
	auto jobs_count = qwSizePlainTextBlocks;
	std::vector<thread_result> thread_jobs(jobs_count);
	for (std::size_t qwCurrentBlock = 0; qwCurrentBlock < jobs_count; ++qwCurrentBlock)
	{
		auto byarrBlockCipherText = _pRijndael->Encrypt(*IV, byarrKey);
		for (uint8_t i = 0; i < 16; i++)
		{
			byarrBlockCipherText[i] ^= (*byarrBufferPlainText)[qwCurrentBlock * 16 + i];
		}

		byarrBufferCipherText->insert(byarrBufferCipherText->end(), byarrBlockCipherText.begin(), byarrBlockCipherText.end());

		// Add Counter += 1 (if dwCurrentBlock % 2 == 0 -> add +1 to hight 64 bits IV) (else -> add +1 to low 64 bits IV)
		if (qwCurrentBlock % 2 == 0)
		{
			FormatIV.qwArray[0]++;
		}
		else
		{
			FormatIV.qwArray[1]++;
		}

		// Update Counter
		IV->clear();
		for (uint8_t i : FormatIV.byArray)
		{
			IV->push_back(i);
		}
	}

	return byarrBufferCipherText;
}

std::shared_ptr<std::vector<uint8_t>> CTR::Decryption(std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	union FormattedGeneratorNumbers
	{
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	// Write IV, Where IV = Counter
	std::shared_ptr<std::vector<uint8_t>> IV = std::make_shared<std::vector<uint8_t>>(byarrBufferCipherText->begin(), byarrBufferCipherText->begin() + 16);
	for (uint8_t i = 0; i < 16; i++)
	{
		FormatIV.byArray[i] = (*IV)[i];
	}

	// Output Buffer
	std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText = std::make_shared<std::vector<uint8_t>>();

	uint64_t qwSizeCipherTextBlocks = byarrBufferCipherText->size() / 16;

	// decrypt blocks
	for (std::size_t qwCurrentBlock = 1; qwCurrentBlock < qwSizeCipherTextBlocks; ++qwCurrentBlock)
	{
		auto byarrBlockPlainText = _pRijndael->Encrypt(*IV, byarrKey);
		for (uint8_t i = 0; i < 16; i++)
		{
			byarrBlockPlainText[i] ^= (*byarrBufferCipherText)[(qwCurrentBlock) * 16 + i];
		}

		byarrBufferPlainText->insert(byarrBufferPlainText->end(), byarrBlockPlainText.begin(), byarrBlockPlainText.end());

		// Revert add Counter +=1 because qwCurrentStartBlock Start with 1;
		// Add Counter += 1 (if dwCurrentBlock % 2 == 1 -> add +1 to hight 64 bits IV) (else -> add +1 to low 64 bits IV)
		if (qwCurrentBlock % 2 == 1)
		{
			FormatIV.qwArray[0]++;
		}
		else
		{
			FormatIV.qwArray[1]++;
		}

		// Update Counter
		IV->clear();
		for (uint8_t i : FormatIV.byArray)
		{
			IV->push_back(i);
		}
	}

	return byarrBufferPlainText;
}
/*End CTR Methods Realization*/

/*Start OFB Methods Realization*/
std::shared_ptr<std::vector<uint8_t>> OFB::Encryption(std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	union FormattedGeneratorNumbers
	{
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	// Get current time in nanoseconds to mt19937_64 Seed
	auto current_time_now = std::chrono::high_resolution_clock::now();
	std::mt19937_64 urandom_generator;
	// Set Seed
	urandom_generator.seed(current_time_now.time_since_epoch().count());

	// Generate IV
	FormatIV.qwArray[0] = urandom_generator();
	FormatIV.qwArray[1] = urandom_generator();

	// Write IV, Where IV = Counter
	std::vector<uint8_t> IV;
	for (uint8_t i : FormatIV.byArray)
	{
		IV.push_back(i);
	}

	// Output Buffer
	std::shared_ptr<std::vector<uint8_t>> arrbyBufferCipherText = std::make_shared<std::vector<uint8_t>>();

	// Insert IV in BufferCipherText
	arrbyBufferCipherText->insert(arrbyBufferCipherText->end(), IV.begin(), IV.end());

	// Check AdditionBlockRatio
	if (byarrBufferPlainText->size() % 16 != 0)
	{
		AdditionBlocksRatio(byarrBufferPlainText);
	}

	std::vector<uint8_t> BlockCipherText;
	for (uint32_t dwCurrentBlock = 0; dwCurrentBlock < (byarrBufferPlainText->size() / 16); dwCurrentBlock++)
	{

		IV = _pRijndael->Encrypt(std::vector<uint8_t>(IV.begin(), IV.end()), byarrKey);

		for (uint8_t i = 0; i < 16; i++)
		{
			BlockCipherText.push_back(IV[i] ^ (*byarrBufferPlainText)[dwCurrentBlock * 16 + i]);
		}

		// Add Cipher Text in Buffer
		arrbyBufferCipherText->insert(arrbyBufferCipherText->end(), BlockCipherText.begin(), BlockCipherText.end());

		BlockCipherText.clear();
	}
	return arrbyBufferCipherText;
}

std::shared_ptr<std::vector<uint8_t>> OFB::Decryption(std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	union FormattedGeneratorNumbers
	{
		uint8_t byArray[16];
		uint64_t qwArray[2];
	};
	FormattedGeneratorNumbers FormatIV;

	// Write IV, Where IV = Counter
	std::vector<uint8_t> IV(byarrBufferCipherText->begin(), byarrBufferCipherText->begin() + 16);
	for (uint8_t i = 0; i < 16; i++)
	{
		FormatIV.byArray[i] = IV[i];
	}

	// Output Buffer
	std::shared_ptr<std::vector<uint8_t>> arrbyBufferPlainText = std::make_shared<std::vector<uint8_t>>();

	std::vector<uint8_t> BlockPlainText;
	for (uint32_t dwCurrentBlock = 1; dwCurrentBlock < (byarrBufferCipherText->size() / 16); dwCurrentBlock++)
	{

		IV = _pRijndael->Encrypt(std::vector<uint8_t>(IV.begin(), IV.end()), byarrKey);
		for (uint8_t i = 0; i < 16; i++)
		{
			BlockPlainText.push_back(IV[i] ^ (*byarrBufferCipherText)[dwCurrentBlock * 16 + i]);
		}

		// Add Cipher Text in Buffer
		arrbyBufferPlainText->insert(arrbyBufferPlainText->end(), BlockPlainText.begin(), BlockPlainText.end());

		BlockPlainText.clear();
	}
	return arrbyBufferPlainText;
}
/*End OFB Methods Realization*/