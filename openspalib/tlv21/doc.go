/*
	Package tlv21 implements TLV with 2 bytes for the type and 1 byte for the length.
	The type field is encoded using big endian.

	This package was written specifically for openspalib and so it contains a feature
	that would otherwise be considered a bug. There can only be once instance of a type
	in a container. Thus if a type in a TLV container is repeated, the parser will append
	it to the "singleton" type Entry.
 */
package tlv21
