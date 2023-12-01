#pragma once

#include "aes_rijndael.h"
#include <thread>
#include <memory>

/*Interface Encryption Mode Class*/
class IEncryptionMode
{
protected:
	std::shared_ptr<Rijndael> _pRijndael{nullptr};

public:
	IEncryptionMode(std::shared_ptr<Rijndael> pRijndael) : _pRijndael(pRijndael){};

	virtual std::shared_ptr<std::vector<uint8_t>> Encryption(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) = 0;

	virtual std::shared_ptr<std::vector<uint8_t>> Decryption(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) = 0;

	void AdditionBlocksRatio(std::shared_ptr<std::vector<uint8_t>> arrbyBufferPublicText);
};

/*ECB Encryption Mode Class*/
class ECB : public IEncryptionMode
{
public:
	ECB(std::shared_ptr<Rijndael> pRijndael) : IEncryptionMode(pRijndael){};

	std::shared_ptr<std::vector<uint8_t>> Encryption(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) override;

	std::shared_ptr<std::vector<uint8_t>> Decryption(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) override;
};

/*CTR Encryption Mode Class*/
class CTR : public IEncryptionMode
{
public:
	CTR(std::shared_ptr<Rijndael> pRijndael) : IEncryptionMode(pRijndael){};

	std::shared_ptr<std::vector<uint8_t>> Encryption(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) override;

	std::shared_ptr<std::vector<uint8_t>> Decryption(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) override;
};

/*OFB Encryption Mode Class*/
class OFB : public IEncryptionMode
{
public:
	OFB(std::shared_ptr<Rijndael> pRijndael) : IEncryptionMode(pRijndael){};

	std::shared_ptr<std::vector<uint8_t>> Encryption(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) override;

	std::shared_ptr<std::vector<uint8_t>> Decryption(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) override;
};
