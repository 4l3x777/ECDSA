#pragma once

/*
Federal Information
Processing Standards Publication 197
November 26, 2001
Announcing the
ADVANCED ENCRYPTION STANDARD (AES)

AUTHOR 4l3x777
*/

#include <string>
#include <vector>
#include <iterator>
#include <memory>

class Rijndael
{
private:
	uint8_t Nb{0}; // number of rows in Matrix State, in standard FIPS197 this value is 4
	uint8_t Nk{0}; // key length variable
	uint8_t Nr{0}; // nuMber of rounds

	std::shared_ptr<std::vector<uint8_t>> Key;		 // array of Key
	std::shared_ptr<std::vector<uint8_t>> RoundKeys; // array of RoundKeys
	/*Crypt Functions*/

	void SubBytes(std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

	void ShiftRows(std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

	void MixColomns(std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

	void AddRoundKey(uint8_t byCurrentRound, std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

	void KeyExpansion();

	/*Decrypt Function*/

	void InvShiftRows(std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

	void InvSubBytes(std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

	void InvMixColomns(std::shared_ptr<std::vector<std::vector<uint8_t>>> State);

public:
	std::vector<uint8_t> Encrypt(const std::vector<uint8_t> &arrbyBlockPlainText, std::shared_ptr<std::vector<uint8_t>> byarrKey);

	std::vector<uint8_t> Decrypt(const std::vector<uint8_t> &arrbyBlockCipherText, std::shared_ptr<std::vector<uint8_t>> byarrKey);

	Rijndael(uint8_t, uint8_t, uint8_t);

	Rijndael() : Rijndael(4, 4, 10){};

	~Rijndael();
};
