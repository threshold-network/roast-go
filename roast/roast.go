// Package ROAST implements BIP340 specialized version of the ROAST protocol.
//
// [ROAST]
//
//	Ruffing T., Ronge V., Jin E., Schneider-Bensch J., Schroder D.,
//	"ROAST: Robust Asynchronous Schnorr Threshold Signatures"
//	<https://eprint.iacr.org/2022/550.pdf>
//
// [FROST]
//
//	Connolly, D., Komlo, C., Goldberg, I., and C. A. Wood, "Two-Round
//	Threshold Schnorr Signatures with FROST", Work in Progress, Internet-Draft,
//	draft-irtf-cfrg-frost-15, 5 December 2023,
//	<https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/>.
//
// [HASH-TO-CURVE]
//
//	Faz-Hernandez, A., Scott, S., Sullivan, N., Wahby, R. S., and C. A. Wood,
//	"Hashing to Elliptic Curves", Work in Progress, Internet-Draft,
//	draft-irtf-cfrg-hash-to-curve- 16, 15 June 2022,
//	<https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16>.
//
// [RFC8017]
//
//	Moriarty, K., Ed., Kaliski, B., Jonsson, J., and A. Rusch, "PKCS #1: RSA
//	Cryptography Specifications Version 2.2", RFC 8017, DOI 10.17487/RFC8017,
//	November 2016,
//	<https://doi.org/10.17487/RFC8017>.
//
// [BIP0340]
//
//	Wuille, P., Nick, J., and Ruffing, T, "Schnorr Signatures for secp256k1",
//	19 January 2020,
//	<https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>.
package roast
