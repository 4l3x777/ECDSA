# ECDSA (```Elliptic Curve Digital Sign Algorithm [PrimeField]```)

## Thanks for projects

+ ```ttmath``` Bignum C++ library https://www.ttmath.org/
+ ```googletest``` GoogleTest - Google Testing and Mocking Framework https://github.com/google/googletest
+ ```thread_pool``` ThreadPool https://github.com/progschj/ThreadPool


## How to use

### Windows

+ copy ```includes``` folder to your project
+ add ```ecdsa.h``` to your source file
+ link ```crypto_pseudo_random_generator.lib``` to your project
+ link ```sha512.lib``` to your project
+ link ```aes.lib``` to your project
+ link ```ecdsa_primefield.lib``` to your project
+ link ```thread_pool.lib``` to your project

### Linux

+ copy ```includes``` folder to your project
+ add ```ecdsa.h``` to your source file
+ link ```libcrypto_pseudo_random_generator.a``` to your project
+ link ```libsha512.a``` to your project
+ link ```libaes.a``` to your project
+ link ```libecdsa_primefield.a``` to your project
+ link ```libthread_pool.a``` to your project

## Examples

+ Example Use NIST Standart P384

```C++
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
```

+ Example Use GOST Standart P512

```C++
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
```

+ Example ECDHE (```Elliptic Curve Diffie-Hellman```)

```C++
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
 // check equals shared secret
 auto result = SecretPointB.getXCoordinate() == SecretPointA.getXCoordinate() ? true : false;
```

## Tests coverage

+ aes
+ crypto_pseudo_random_generator
+ ecdsa (GOST_256, GOST_512, NIST_192 ... curves)
+ ecdsa_primefield
+ sha512
