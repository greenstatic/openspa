/*
	Package tlv8 implements TLV with 1 bytes for the type and 1 byte for the length.

	Type field can be anything from 1-255. Type=0 is reserved, internally it is used as a separator between
	two TLV8 items of the same type.

	The library is not safe for concurrency. It is up to the caller to ensure multiple calls from different goroutines
	are not being triggered to the same Container
*/
package tlv8
