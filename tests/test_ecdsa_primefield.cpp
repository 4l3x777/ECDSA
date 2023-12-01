#include <gtest/gtest.h>

#include <ecdsa_primefield.h>
#include <crypto_pseudo_random_generator.h>
#include <string>

/*Unit Test ECDSA Algorithm*/
class ECDSATest : public ::testing::Test
{
};

TEST_F(ECDSATest, NISTCurveP521)
{
	auto rInstanceECDSA = std::make_shared<ecdsa_pf>(
		bigint("-3"),
		bigint("1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984"),
		bigint("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"),
		bigint("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846"),
		bigint("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784"),
		bigint("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"));

	std::string d("1234567890098765432112345678900987654321");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = rInstanceECDSA->CreateKeyCheckDigitalSign(d);

	// CreateDigitalSign
	std::string Message("Hello Alice! My name is Bob!");
	std::pair<std::string, std::string> DigitalSign = rInstanceECDSA->CreateDigitalSign(d, Message);

	// CheckDigitalSign
	bool result = rInstanceECDSA->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);
	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, NISTCurveP192)
{
	auto rInstanceECDSA = std::make_shared<ecdsa_pf>(
		bigint("-3"),
		bigint("2455155546008943817740293915197451784769108058161191238065"),
		bigint("6277101735386680763835789423207666416083908700390324961279"),
		bigint("602046282375688656758213480587526111916698976636884684818"),
		bigint("174050332293622031404857552280219410364023488927386650641"),
		bigint("6277101735386680763835789423176059013767194773182842284081"));

	std::string d("1234567890098765432112345678900987654321");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = rInstanceECDSA->CreateKeyCheckDigitalSign(d);

	// CreateDigitalSign
	std::string Message("Hello Alice! My name is Bob!");
	std::pair<std::string, std::string> DigitalSign = rInstanceECDSA->CreateDigitalSign(d, Message);

	// CheckDigitalSign
	bool result = rInstanceECDSA->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}

TEST_F(ECDSATest, GOSTCurve256)
{
	auto rInstanceECDSA = std::make_shared<ecdsa_pf>(
		bigint("7"),
		bigint("43308876546767276905765904595650931995942111794451039583252968842033849580414"),
		bigint("57896044618658097711785492504343953926634992332820282019728792003956564821041"),
		bigint("2"),
		bigint("4018974056539037503335449422937059775635739389905545080690979365213431566280"),
		bigint("57896044618658097711785492504343953927082934583725450622380973592137631069619"));

	std::string d("1234567890098765432112345678900987654321");

	// CreateKeyCheckDigitalSign
	std::pair<std::string, std::string> KeyCheckDigitalSign = rInstanceECDSA->CreateKeyCheckDigitalSign(d);

	// CreateDigitalSign
	std::string Message("Hello Alice! My name is Bob!");
	std::pair<std::string, std::string> DigitalSign = rInstanceECDSA->CreateDigitalSign(d, Message);

	// CheckDigitalSign
	bool result = rInstanceECDSA->CheckDigitalSign(DigitalSign, Message, KeyCheckDigitalSign);

	ASSERT_EQ(result, true);
}