# TLV8
Binary encoding scheme based on the [Type-length-value](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value)
scheme.
The *8* in *TLV8* denotes it uses 8-bits for the *Type* and *Length* field.
The purpose of this is to strike a balance between expandability and space constraints due to OpenSPA's limited protocol 
payload size. 

Encoding scheme (a single TLV8 item):
```
| Type (1 byte) | Length (1 byte) | Value |
```

* Length: the length of the *Value* field
* Value: binary data that is encoded dependent on the Type

Encoding rules:
* A length of 0 is valid, which means the Value portion of the field is skipped
* Encoded values of length <= 255 (2^8) should fit into a single TLV8 item
* Encoded values of length > 255 need to be fragmented
* A fragmented item requires containing multiple sequential TLV8 items, each TLV8 item containing that fragmented items 
  value length
* A fragmented item requires all but the last item to be of length 255
* Multiple non-fragmented TLV8 items with the same Type are allowed only if seperated by a TLV8 item of a different type (or the Type 
  separator, see rule below) 
* Type 0x00 is a separator and has the implicit length of 0
