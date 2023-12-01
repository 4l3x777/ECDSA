#pragma once

/*
Federal Information
Processing Standards Publication 197
November 26, 2001
Announcing the
ADVANCED ENCRYPTION STANDARD (AES)
REALIZATION AES 128/192/256 Block Cipher
AUTHOR 4l3x777
*/

/*
	ANNOTATION:
-> When you are create instance of AES_(128/192/256) the default encryption mode is ECB encryption mode
-> SetEncryptionMode allows change encryption mode in Runtime
-> EncryptionModeId is:
	--> '0' - ECB encryption mode;
	--> '1' - CTR encryption mode;
	--> 'other'	- save previous mode;
->
*/

#include "aes_rijndael.h"
#include "aes_encryption_mode.h"

#include <memory>

/*Interface class AES*/
class IAES
{
protected:
	std::shared_ptr<IEncryptionMode> _pEncryptionMode{nullptr};
	std::shared_ptr<Rijndael> _pRijndael{nullptr};
	uint8_t Nb{0};
	uint8_t Nk{0};
	uint8_t Nr{0};

public:
	virtual std::shared_ptr<std::vector<uint8_t>> Encrypt(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) = 0;
	virtual std::shared_ptr<std::vector<uint8_t>> Decrypt(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) = 0;
	void SetEncryptionMode(uint8_t EncryptionModeID);
};

/*AES 128 Class*/
class AES_128 : public IAES
{
public:
	std::shared_ptr<std::vector<uint8_t>> Encrypt(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) override;
	std::shared_ptr<std::vector<uint8_t>> Decrypt(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) override;

	AES_128()
	{
		Nb = 4;
		Nk = 4;
		Nr = 10;
		_pRijndael = std::make_shared<Rijndael>(Nb, Nk, Nr);
		_pEncryptionMode = std::make_shared<ECB>(_pRijndael);
	}
};

/*AES 192 Class*/
class AES_192 : public IAES
{
public:
	std::shared_ptr<std::vector<uint8_t>> Encrypt(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) override;
	std::shared_ptr<std::vector<uint8_t>> Decrypt(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) override;

	AES_192()
	{
		Nb = 4;
		Nk = 6;
		Nr = 12;
		_pRijndael = std::make_shared<Rijndael>(Nb, Nk, Nr);
		_pEncryptionMode = std::make_shared<ECB>(_pRijndael);
	}
};

/*AES 256 Class*/
class AES_256 : public IAES
{
public:
	std::shared_ptr<std::vector<uint8_t>> Encrypt(std::shared_ptr<std::vector<uint8_t>> PlainText, std::shared_ptr<std::vector<uint8_t>> Key) override;
	std::shared_ptr<std::vector<uint8_t>> Decrypt(std::shared_ptr<std::vector<uint8_t>> CipherText, std::shared_ptr<std::vector<uint8_t>> Key) override;

	AES_256()
	{
		Nb = 4;
		Nk = 8;
		Nr = 14;
		_pRijndael = std::make_shared<Rijndael>(Nb, Nk, Nr);
		_pEncryptionMode = std::make_shared<ECB>(_pRijndael);
	}
};
