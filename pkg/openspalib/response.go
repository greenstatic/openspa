package openspalib

type ResponseData struct {
}

type Response struct {
	Body Container
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
