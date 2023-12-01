#pragma once

/*
FIPS PUB 180-4
FEDERAL INFORMATION PROCESSING STANDARDS
PUBLICATION
Secure Hash Standard (SHS)
CATEGORY: COMPUTER SECURITY SUBCATEGORY: CRYPTOGRAPHY

AUTHOR 4l3x777
REALIZATION SHA512 HASH FUNCTION
*/

#include <cstring>
#include <vector>
#include <memory>

class SHA512
{
private:
	uint64_t H0{0};
	uint64_t H1{0};
	uint64_t H2{0};
	uint64_t H3{0};
	uint64_t H4{0};
	uint64_t H5{0};
	uint64_t H6{0};
	uint64_t H7{0};

	std::shared_ptr<std::vector<uint8_t>> byarrMessage{nullptr};
	std::unique_ptr<std::vector<uint64_t>> W{nullptr};
	std::unique_ptr<std::vector<uint64_t>> M{nullptr};

	void PaddingTheMessage();

	void Preprocessing();

	void HashCompulation();

	void HashComplulationBlock();

	uint64_t ROTR(uint64_t x, uint8_t n);

	uint64_t SHR(uint64_t x, uint8_t n);

	uint64_t SIGMA0(uint64_t x);

	uint64_t SIGMA1(uint64_t x);

	uint64_t sigma0(uint64_t x);

	uint64_t sigma1(uint64_t x);

public:
	std::shared_ptr<std::vector<uint8_t>> GetHash(std::shared_ptr<std::vector<uint8_t>> Message);
};
