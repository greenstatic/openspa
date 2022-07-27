package openspalib

import "github.com/greenstatic/openspa/pkg/openspalib/tlv"

type ResponseData struct {
}

type Response struct {
	Body tlv.Container
}

func NewResponse(ResponseData) (*Response, error) {
	r := &Response{}
	return r, nil
}

func (r *Response) Marshal() ([]byte, error) {
	return nil, nil
}

func ResponseUnmarshal(b []byte) (*Response, error) {
	return nil, nil
}
