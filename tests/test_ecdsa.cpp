#include <ecdsa.h>
#include <gtest/gtest.h>
#include <string>
#include <iostream>
#include <crypto_pseudo_random_generator.h>
#include <ecdsa_primefield.h>

/*Unit Test ECDSA Algorithm*/
class ECDSATest : public ::testing::Test
{
};

TEST_F(ECDSATest, TEST_ECDSA_GOST_256)
{
	auto GOST = std::make_shared<ECDSA_GOST_256>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = GOST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = GOST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = GOST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_GOST_512)
{
	auto GOST = std::make_shared<ECDSA_GOST_512>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = GOST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = GOST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = GOST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_192)
{
	auto NIST = std::make_shared<ECDSA_NIST_192>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = NIST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = NIST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = NIST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_224)
{
	auto NIST = std::make_shared<ECDSA_NIST_224>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = NIST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = NIST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = NIST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_256)
{
	auto NIST = std::make_shared<ECDSA_NIST_256>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = NIST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = NIST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = NIST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_384)
{
	auto NIST = std::make_shared<ECDSA_NIST_384>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = NIST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = NIST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = NIST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, TEST_ECDSA_NIST_521)
{
	auto NIST = std::make_shared<ECDSA_NIST_521>();

	std::string SecretKey("1234567890098765432112345678900987654321");
	std::string Message("Hello Alice! My name is Bob!");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = NIST->CreateKeyCheckDigitalSign(SecretKey);

	// CreateDigitalSign
	std::pair<std::string, std::string> DigitalSign = NIST->CreateDigitalSign(SecretKey, Message);

	// Message += "?"; //Change Message  (Attack to integrity)

	// CheckDigitalSign
	bool result = NIST->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

//https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman
TEST_F(ECDSATest, TEST_ECDHE_SHARED_SECRET)
{
	auto NIST = std::make_shared<ECDSA_NIST_521>();
	// secret parameter UserA
	bigint dA;
	// secret parameter UserB
	bigint dB;

	//Generate Pseudo Random Number
	CryptoPseudoRandomGenerator generator;
	auto pseudo_random_number = generator.generate(1024);

	//Get Secret Key for Elliptic Curve UserA
	dA.FromString(NIST->hexStr(pseudo_random_number), 16);

	//Get Public Elliptic Curve Point UserA
	auto QA = NIST->MultiplyOnBasePoint(dA);

	//Generate Pseudo Random Number
	pseudo_random_number = generator.generate(1024);

	//Get Secret Key for Elliptic Curve UserB
	dB.FromString(NIST->hexStr(pseudo_random_number), 16);

	//Get Public Elliptic Curve Point UserB
	auto QB = NIST->MultiplyOnBasePoint(dB);

	//Calculate Common Session Key for UserA
	ecpoint FriendQB(NIST);
	FriendQB.setCoordinate(
		std::string(QB.first),
		std::string(QB.second)
	);
	ecpoint SecretPointA = FriendQB*dA;

	//Calculate Common Session Key for UserB
	ecpoint FriendQA(NIST);
	FriendQA.setCoordinate(
		std::string(QA.first),
		std::string(QA.second)
	);
	ecpoint SecretPointB = FriendQA*dB;

	ASSERT_STREQ(
		SecretPointB.getXCoordinate().c_str(), 
		SecretPointA.getXCoordinate().c_str()
	);
}