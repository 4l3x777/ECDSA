#pragma once

#define TTMATH_NOASM
#include <ttmath/ttmath.h>
#include <ttmath/ttmathint.h>

#include <iostream>
#include <string>
#include <memory>

using bigint = ttmath::Int<32>;

/*Class ECDSA_PrimeField*/
class ecdsa_pf : public std::enable_shared_from_this<ecdsa_pf>
{
private:
	/*Curve Coefficients*/
	bigint _a;	// Coefficient 'a' of Curve equal y^2 = x^3 + a*x + b (mod p) | Anallogically abbreviation in GOST 34.10-2012
	bigint _b;	// Coefficient 'b' of Curve equal y^2 = x^3 + a*x + b (mod p) | Anallogically abbreviation in GOST 34.10-2012
	bigint _p;	// Prime module of Curve equal y^2 = x^3 + a*x + b (mod p) | Anallogically abbreviation in GOST 34.10-2012
	bigint _Gx; // Coordinate 'x' of Point G of Elliptical Curve [ y^2 = x^3 + a*x + b (mod p) ] order n | In GOST 34.10-2012 it is 'x' coordinate of point P
	bigint _Gy; // Coordinate 'y' of Point G of Elliptical Curve [ y^2 = x^3 + a*x +b (mod p) ] order n | In GOST 34.10-2012 it is 'y' coordinate of point P
	bigint _n;	// Order of SubGroup of Points of Elliptical Curve [ y^2 = x^3 + a*x + b (mod p) ] | In GOST 34.10-2012 it is 'q' parametr

public:
	std::string hexStr(std::shared_ptr<std::vector<uint8_t>> data);

	// Return Public parameters : first - 'r', second - 's'
	std::pair<std::string, std::string> CreateDigitalSign(const std::string &PrivateKeyDigitalSign, const std::string &Message);

	bool CheckDigitalSign(const std::pair<std::string, std::string> &DigitalSign, const std::string &Message, const std::pair<std::string, std::string> &KeyCheckDigitalSign);

	// Return KeyCheckDigitalSign <=>  Public Elliptic Curve Point Q : first - 'x' coordinate of Q point, second - 'y' coordinate of Q point, [PrivateKeyDigitalSign is Big number in dec system]
	std::pair<std::string, std::string> CreateKeyCheckDigitalSign(const std::string &PrivateKeyDigitalSign);

	std::pair<std::string, std::string> MultiplyOnBasePoint(const bigint &Number);

	ecdsa_pf(const bigint &a, const bigint &b, const bigint &p, const bigint &Gx, const bigint &Gy, const bigint &n);

	friend class ecpoint;
};

/*Class ecpoint*/
class ecpoint
{
private:
	/*Elliptical Curve Point Coordinates 'x' and 'y' */
	bigint _x;
	bigint _y;
	std::shared_ptr<ecdsa_pf> _parentECDSA;

	ecpoint DoubleAndAdd(const bigint &k, const ecpoint &point);

	static bigint ReverseElementInField(const bigint &Element, const bigint &Module);

	static void ExtendedEuclidAlgorithm(bigint &a, bigint &b, bigint &x, bigint &y, bigint &d);

public:
	void setCoordinate(const std::string &x, const std::string &y);

	std::string getXCoordinate();

	std::string getYCoordinate();

	ecpoint &operator=(const ecpoint &rhs);

	ecpoint operator+(const ecpoint &rhs);

	ecpoint operator*(const bigint &rhs);

	bool operator==(const ecpoint &rhs);

	ecpoint(std::shared_ptr<ecdsa_pf> parentECDSA);

	~ecpoint();

	friend class ecdsa_pf;
};