package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvent_SetHeader(t *testing.T) {
	evt := Event{
		Headers: EventHeaders{},
		Payload: "blah",
	}

	testHeader := "random-header"

	assert.Equal(t, "", evt.Header(testHeader))

	testHeaderInput := "test"

	evt.SetHeader(testHeader, testHeaderInput)

	assert.Equal(t, testHeaderInput, evt.Header(testHeader))
}

func TestFilter_FlattenIfaceSlice(t *testing.T) {
	testSlice := []interface{}{[]string{"a", "b", "c"}, []int{1, 2, 3}, "bruh"}
	expected := []interface{}{"a", "b", "c", 1, 2, 3, "bruh"}
	assert.Equal(t, expected, flattenIfaceArr(testSlice))
}
