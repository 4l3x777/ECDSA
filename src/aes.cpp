#include <aes.h>

/*Start InterfaceAES Methods Realization*/
void IAES::SetEncryptionMode(uint8_t EncryptionModeID)
{
	switch (EncryptionModeID)
	{
	// EncryptionModeID = '0' is ECB mode
	case 0:
	{
		_pEncryptionMode = std::make_shared<ECB>(_pRijndael);
		break;
	}
	// EncryptionModeID = '1' is CTR mode
	case 1:
	{
		_pEncryptionMode = std::make_shared<CTR>(_pRijndael);
		break;
	}
	// EncryptionModeID = '2' is OFB mode
	case 2:
	{
		_pEncryptionMode = std::make_shared<OFB>(_pRijndael);
		break;
	}
	default:
		break;
	}
}
/*End InterfaceAES Methods Realization*/

/*Start AES 128 Methods Realization*/
std::shared_ptr<std::vector<uint8_t>> AES_128::Encrypt(std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 16 == 0))
	{
		return _pEncryptionMode->Encryption(byarrBufferPlainText, byarrKey);
	}
	else
	{
		return nullptr;
	}
}

std::shared_ptr<std::vector<uint8_t>> AES_128::Decrypt(std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 16 == 0))
	{
		return _pEncryptionMode->Decryption(byarrBufferCipherText, byarrKey);
	}
	else
	{
		return nullptr;
	}
}
/*End AES 128 Methods Realization*/

/*Start AES 192 Methods Realization*/
std::shared_ptr<std::vector<uint8_t>> AES_192::Encrypt(std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 24 == 0))
	{
		return _pEncryptionMode->Encryption(byarrBufferPlainText, byarrKey);
	}
	else
	{
		return nullptr;
	}
}

std::shared_ptr<std::vector<uint8_t>> AES_192::Decrypt(std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 24 == 0))
	{
		return _pEncryptionMode->Decryption(byarrBufferCipherText, byarrKey);
	}
	else
	{
		return nullptr;
	}
}
/*End AES 192 Methods Realization*/

/*Start AES 256 Methods Realization*/
std::shared_ptr<std::vector<uint8_t>> AES_256::Encrypt(std::shared_ptr<std::vector<uint8_t>> byarrBufferPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	if ((!byarrBufferPlainText->empty() && byarrBufferPlainText != nullptr) && (!byarrKey->empty() && byarrKey->size() % 32 == 0))
	{
		return _pEncryptionMode->Encryption(byarrBufferPlainText, byarrKey);
	}
	else
	{
		return nullptr;
	}
}

std::shared_ptr<std::vector<uint8_t>> AES_256::Decrypt(std::shared_ptr<std::vector<uint8_t>> byarrBufferCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey)
{
	if ((!byarrBufferCipherText->empty() && byarrBufferCipherText != nullptr && byarrBufferCipherText->size() % 16 == 0) && (!byarrKey->empty() && byarrKey->size() % 32 == 0))
	{
		return _pEncryptionMode->Decryption(byarrBufferCipherText, byarrKey);
	}
	else
	{
		return nullptr;
	}
}
/*End AES 256 Methods Realization*/