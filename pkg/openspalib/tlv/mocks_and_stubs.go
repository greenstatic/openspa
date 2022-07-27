package tlv

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/emirpasic/gods/maps"
	"github.com/emirpasic/gods/maps/hashmap"
	"github.com/stretchr/testify/mock"
)

var _ Container = &ContainerMock{}

type ContainerMock struct {
	mock.Mock
}

func NewContainerMock() *ContainerMock {
	c := &ContainerMock{}
	return c
}

func (c *ContainerMock) GetByte(key uint8) (b byte, exists bool) {
	args := c.Mock.Called(key)
	return args.Get(0).(byte), args.Bool(1)
}

func (c *ContainerMock) GetBytes(key uint8) (b []byte, exists bool) {
	args := c.Mock.Called(key)
	return args.Get(0).([]byte), args.Bool(1)
}

func (c *ContainerMock) SetByte(key uint8, value byte) {
	c.Mock.Called(key, value)
}

func (c *ContainerMock) SetBytes(key uint8, value []byte) {
	c.Mock.Called(key, value)
}

func (c *ContainerMock) Remove(key uint8) {
	c.Mock.Called(key)
}

func (c *ContainerMock) Bytes() []byte {
	args := c.Mock.Called()
	return args.Get(0).([]byte)
}

func (c *ContainerMock) Size() int {
	args := c.Mock.Called()
	return args.Int(0)
}

func (c *ContainerMock) NoEntries() int {
	args := c.Mock.Called()
	return args.Int(0)
}

var _ Container = &ContainerStub{}

type ContainerStub struct {
	m    maps.Map
	lock sync.Mutex
}

func NewContainerStub() *ContainerStub {
	c := &ContainerStub{}

	c.m = hashmap.New()

	return c
}

func (c *ContainerStub) GetByte(key uint8) (b byte, exists bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	v, ok := c.m.Get(key)
	if !ok {
		return 0, false
	}

	buf, ok := v.([]byte)
	if !ok {
		panic(fmt.Sprintf("Expected type []byte but received: %s", reflect.TypeOf(buf)))
	}

	return buf[0], true
}

func (c *ContainerStub) GetBytes(key uint8) (b []byte, exists bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	v, ok := c.m.Get(key)
	if !ok {
		return nil, false
	}

	buf, ok := v.([]byte)
	if !ok {
		panic(fmt.Sprintf("Expected type []byte but received: %s", reflect.TypeOf(buf)))
	}

	return buf, true
}

func (c *ContainerStub) SetByte(key uint8, value byte) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.m.Put(key, []byte{value})
}

func (c *ContainerStub) SetBytes(key uint8, value []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.m.Put(key, value)
}

func (c *ContainerStub) Remove(key uint8) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.m.Remove(key)
}

func (c *ContainerStub) Bytes() []byte {
	// TODO
	return nil
}

func (c *ContainerStub) Size() int {
	return len(c.Bytes())
}

func (c *ContainerStub) NoEntries() int {
	c.lock.Lock()
	defer c.lock.Unlock()

	return len(c.m.Values())
}
