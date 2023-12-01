#include <gtest/gtest.h>
#include <memory>

#include <aes.h>
#include <aes_rijndael.h>

/*Unit Test AES 128/192/256 BlocksCipher*/

class TestAES : public ::testing::Test
{
};

/*Big Input Size TESTS*/
// ECB
TEST_F(TestAES, AES128_ECB)
{
	AES_128 aes;
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);

	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

TEST_F(TestAES, AES192_ECB)
{
	AES_192 aes;
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

TEST_F(TestAES, AES256_ECB)
{
	AES_256 aes;
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

// CTR
TEST_F(TestAES, AES128_CTR)
{
	AES_128 aes;
	aes.SetEncryptionMode(1);
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

TEST_F(TestAES, AES192_CTR)
{
	AES_192 aes;
	aes.SetEncryptionMode(1);
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

TEST_F(TestAES, AES256_CTR)
{
	AES_256 aes;
	aes.SetEncryptionMode(1);
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

// OFB
TEST_F(TestAES, AES128_OFB)
{
	AES_128 aes;
	aes.SetEncryptionMode(2);
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

TEST_F(TestAES, AES192_OFB)
{
	AES_192 aes;
	aes.SetEncryptionMode(2);
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}

TEST_F(TestAES, AES256_OFB)
{
	AES_256 aes;
	aes.SetEncryptionMode(2);
	auto key = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f});
	auto PT = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(10485760, 'a'));
	auto calcCT = aes.Encrypt(PT, key);
	auto calcPT = aes.Decrypt(calcCT, key);
	for (uint64_t i = 0; i < PT->size(); i++)
	{
		EXPECT_EQ((*calcPT)[i], (*PT)[i]);
	}
}