#include <gtest/gtest.h>
#include <crypto_pseudo_random_generator.h>

class TestCryptoPseudoRandomGenerator : public ::testing::Test
{
};

TEST_F(TestCryptoPseudoRandomGenerator, CorrectGenerate)
{
	CryptoPseudoRandomGenerator generator;
	ASSERT_EQ(generator.generate(10485760)->size(), 10485760);
}