#pragma once

#include <iostream>
#include <vector>
#include <memory>

class CryptoPseudoRandomGenerator
{
public:
	std::shared_ptr<std::vector<uint8_t>> generate(uint64_t PRNSizeInBytes);
};
