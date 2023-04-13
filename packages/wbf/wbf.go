package wbf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	err := encodeValue(reflect.ValueOf(v), &b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func WriteValue(v any, w io.Writer) error {
	return encodeValue(reflect.ValueOf(v), w)
}

func MustMarshal(v any) []byte {
	r, err := Marshal(v)
	if err != nil {
		panic(err)
	}
	return r
}

func encodeValue(v reflect.Value, w io.Writer) error {
	if m := v.MethodByName("WBFWrite"); m.IsValid() && !m.IsZero() {
		r := m.Call([]reflect.Value{reflect.ValueOf(w)})
		if !r[0].IsZero() {
			return r[0].Interface().(error)
		}
		return nil
	}

	kind := v.Kind()
	switch kind {
	case reflect.Bool:
		return encodeBool(v.Bool(), w)
	case reflect.Int8:
		return encodeInt8(int8(v.Int()), w)
	case reflect.Uint8:
		return encodeUint8(uint8(v.Uint()), w)
	case reflect.Int16:
		return encodeInt16(int16(v.Int()), w)
	case reflect.Uint16:
		return encodeUint16(uint16(v.Uint()), w)
	case reflect.Int32:
		return encodeInt32(int32(v.Int()), w)
	case reflect.Uint32:
		return encodeUint32(uint32(v.Uint()), w)
	case reflect.Int64:
		return encodeInt64(v.Int(), w)
	case reflect.Uint64:
		return encodeUint64(v.Uint(), w)
	case reflect.Struct:
		return encodeStruct(v, w)
	case reflect.Array, reflect.Slice:
		return encodeSlice(v, w)
	case reflect.Pointer:
		if v.IsZero() {
			return fmt.Errorf("cannot encode a nil pointer")
		}
		return encodeValue(v.Elem(), w)
	default:
		return fmt.Errorf("cannot encode value of type %s", kind)
	}
}

func encodeBool(v bool, w io.Writer) error {
	var x byte = 0
	if v {
		x = 1
	}
	_, err := w.Write([]byte{x})
	return err
}

func encodeInt8(n int8, w io.Writer) error {
	_, err := w.Write([]byte{byte(n)})
	return err
}

func encodeUint8(n uint8, w io.Writer) error {
	_, err := w.Write([]byte{byte(n)})
	return err
}

func encodeInt16(n int16, w io.Writer) error {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(n))
	_, err := w.Write(b[:])
	return err
}

func encodeUint16(n uint16, w io.Writer) error {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func encodeInt32(n int32, w io.Writer) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(n))
	_, err := w.Write(b[:])
	return err
}

func encodeUint32(n uint32, w io.Writer) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func encodeInt64(n int64, w io.Writer) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(n))
	_, err := w.Write(b[:])
	return err
}

func encodeUint64(n uint64, w io.Writer) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func encodeSlice(v reflect.Value, w io.Writer) error {
	n := v.Len()
	if n == 0 {
		return nil
	}
	if v.Index(0).Kind() == reflect.Uint8 {
		_, err := w.Write(v.Bytes())
		return err
	}
	for i := 0; i < n; i++ {
		err := encodeValue(v.Index(i), w)
		if err != nil {
			return err
		}
	}
	return nil
}

func encodeStruct(v reflect.Value, w io.Writer) error {
	t := v.Type()
	n := v.NumField()
	for i := 0; i < n; i++ {
		fv := v.Field(i)
		tag := t.Field(i).Tag.Get("wbf")
		switch tag {
		case "u32size":
			err := encodeSlice32(fv, w)
			if err != nil {
				return err
			}
		case "optional":
			err := encodeOptional(fv, w)
			if err != nil {
				return err
			}
		case "":
			err := encodeValue(fv, w)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("no handler for wbf tag %q", tag)
		}
	}
	return nil
}

func encodeOptional(v reflect.Value, w io.Writer) error {
	if v.Kind() != reflect.Pointer {
		return errors.New("optional cannot be applied to non-pointer")
	}
	exists := !v.IsZero()
	err := encodeBool(exists, w)
	if err != nil {
		return err
	}
	if exists {
		return encodeValue(v, w)
	}
	return nil
}

func encodeSlice32(v reflect.Value, w io.Writer) error {
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		size := uint32(v.Len())
		err := encodeUint32(size, w)
		if err != nil {
			return err
		}
		return encodeValue(v, w)
	default:
		return errors.New("u32size cannot be applied to non-slice value")
	}
}

func Unmarshal(v any, b []byte) error {
	rest, err := ReadValue(v, b)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("cannot unmarshal value: remaining bytes")
	}
	return nil
}

func ReadValue(v any, b []byte) ([]byte, error) {
	pointer := reflect.ValueOf(v)
	if pointer.Kind() != reflect.Pointer {
		return nil, fmt.Errorf("cannot unmarshal into a non-pointer")
	}
	if pointer.IsZero() {
		return nil, fmt.Errorf("cannot unmarshal into a nil pointer")
	}
	return decodeValue(pointer.Elem(), b)
}

func MustUnmarshal(v any, b []byte) {
	err := Unmarshal(v, b)
	if err != nil {
		panic(err)
	}
}

func decodeValue(v reflect.Value, b []byte) ([]byte, error) {
	if _, ok := v.Type().MethodByName("WBFRead"); ok {
		v.Set(reflect.New(v.Elem().Type()))
		r := v.MethodByName("WBFRead").Call([]reflect.Value{reflect.ValueOf(b)})
		if !r[1].IsZero() {
			err := r[1].Interface().(error)
			return nil, err
		}
		b = r[0].Bytes()
		return b, nil
	}
	kind := v.Kind()
	var err error
	switch kind {
	case reflect.Bool:
		var r bool
		r, b, err = decodeBool(b)
		if err != nil {
			return nil, err
		}
		v.SetBool(r)
	case reflect.Int8:
		var r int8
		r, b, err = decodeInt8(b)
		if err != nil {
			return nil, err
		}
		v.SetInt(int64(r))
	case reflect.Uint8:
		var r uint8
		r, b, err = decodeUint8(b)
		if err != nil {
			return nil, err
		}
		v.SetUint(uint64(r))
	case reflect.Int16:
		var r int16
		r, b, err = decodeInt16(b)
		if err != nil {
			return nil, err
		}
		v.SetInt(int64(r))
	case reflect.Uint16:
		var r uint16
		r, b, err = decodeUint16(b)
		if err != nil {
			return nil, err
		}
		v.SetUint(uint64(r))
	case reflect.Int32:
		var r int32
		r, b, err = decodeInt32(b)
		if err != nil {
			return nil, err
		}
		v.SetInt(int64(r))
	case reflect.Uint32:
		var r uint32
		r, b, err = decodeUint32(b)
		if err != nil {
			return nil, err
		}
		v.SetUint(uint64(r))
	case reflect.Int64:
		var r int64
		r, b, err = decodeInt64(b)
		if err != nil {
			return nil, err
		}
		v.SetInt(r)
	case reflect.Uint64:
		var r uint64
		r, b, err = decodeUint64(b)
		if err != nil {
			return nil, err
		}
		v.SetUint(r)
	case reflect.Struct:
		return decodeStruct(v, b)
	case reflect.Array:
		return decodeSlice(v.Slice(0, v.Len()), b)
	case reflect.Slice:
		return decodeSlice(v, b)
	case reflect.Pointer:
		v.Set(reflect.New(v.Elem().Type()))
		return decodeValue(v.Elem(), b)
	default:
		return nil, fmt.Errorf("cannot decode a value of type %s", kind)
	}
	return b, nil
}

func decodeBool(b []byte) (bool, []byte, error) {
	if len(b) < 1 {
		return false, nil, fmt.Errorf("cannot decode bool value: len(b) != 1")
	}
	return b[0] != 0, b[1:], nil
}

func decodeInt8(b []byte) (int8, []byte, error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("cannot decode int8 value: len(b) != 1")
	}
	return int8(b[0]), b[1:], nil
}

func decodeUint8(b []byte) (uint8, []byte, error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("cannot decode uint8 value: len(b) != 1")
	}
	return b[0], b[1:], nil
}

func decodeInt16(b []byte) (int16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, fmt.Errorf("cannot decode int16 value: len(b) != 2")
	}
	return int16(binary.LittleEndian.Uint16(b)), b[2:], nil
}

func decodeUint16(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, fmt.Errorf("cannot decode uint16 value: len(b) != 2")
	}
	return binary.LittleEndian.Uint16(b), b[2:], nil
}

func decodeInt32(b []byte) (int32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("cannot decode int32 value: len(b) != 4")
	}
	return int32(binary.LittleEndian.Uint32(b)), b[4:], nil
}

func decodeUint32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("cannot decode uint32 value: len(b) != 4")
	}
	return binary.LittleEndian.Uint32(b), b[4:], nil
}

func decodeInt64(b []byte) (int64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("cannot decode int64 value: len(b) != 8")
	}
	return int64(binary.LittleEndian.Uint64(b)), b[8:], nil
}

func decodeUint64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("cannot decode uint64 value: len(b) != 8")
	}
	return binary.LittleEndian.Uint64(b), b[8:], nil
}

func decodeStruct(v reflect.Value, b []byte) ([]byte, error) {
	t := v.Type()
	n := v.NumField()
	for i := 0; i < n; i++ {
		fv := v.Field(i)
		tag := t.Field(i).Tag.Get("wbf")
		switch tag {
		case "u32size":
			var err error
			b, err = decodeSlice32(fv, b)
			if err != nil {
				return nil, err
			}
		case "optional":
			var err error
			b, err = decodeOptional(fv, b)
			if err != nil {
				return nil, err
			}
		case "":
			var err error
			b, err = decodeValue(fv, b)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("no handler for wbf tag %q", tag)
		}
	}
	return b, nil
}

func decodeOptional(v reflect.Value, b []byte) ([]byte, error) {
	if v.Kind() != reflect.Pointer {
		return nil, errors.New("optional cannot be applied to non-pointer")
	}
	var exists bool
	var err error
	exists, b, err = decodeBool(b)
	if err != nil {
		return nil, err
	}
	if !exists {
		if !v.IsZero() {
			v.Set(reflect.Zero(v.Type()))
		}
		return b, nil
	}
	newValue := reflect.New(v.Type().Elem())
	v.Set(newValue)
	return decodeValue(v, b)
}

func decodeSlice32(v reflect.Value, b []byte) ([]byte, error) {
	var n uint32
	var err error
	n, b, err = decodeUint32(b)
	if err != nil {
		return nil, err
	}
	v.Set(reflect.MakeSlice(v.Type(), int(n), int(n)))
	return decodeSlice(v, b)
}

func decodeSlice(v reflect.Value, b []byte) ([]byte, error) {
	n := v.Len()
	if n == 0 {
		return b, nil
	}
	if v.Index(0).Kind() == reflect.Uint8 {
		if len(b) < n {
			return nil, fmt.Errorf("cannot decode byte slice: end of data")
		}
		copied := reflect.Copy(v, reflect.ValueOf(b[:n]))
		if copied != n {
			panic("inconsistency")
		}
		return b[n:], nil
	}
	for i := 0; i < n; i++ {
		var err error
		b, err = decodeValue(v.Index(i), b)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}
