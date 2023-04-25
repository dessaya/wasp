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
	err := writeValue(reflect.ValueOf(v), &b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func WriteValue(v any, w io.Writer) error {
	return writeValue(reflect.ValueOf(v), w)
}

func MustMarshal(v any) []byte {
	r, err := Marshal(v)
	if err != nil {
		panic(err)
	}
	return r
}

func writeValue(v reflect.Value, w io.Writer) error {
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
		return writeBool(v.Bool(), w)
	case reflect.Int8:
		return writeInt8(int8(v.Int()), w)
	case reflect.Uint8:
		return writeUint8(uint8(v.Uint()), w)
	case reflect.Int16:
		return writeInt16(int16(v.Int()), w)
	case reflect.Uint16:
		return writeUint16(uint16(v.Uint()), w)
	case reflect.Int32:
		return writeInt32(int32(v.Int()), w)
	case reflect.Uint32:
		return writeUint32(uint32(v.Uint()), w)
	case reflect.Int64:
		return writeInt64(v.Int(), w)
	case reflect.Uint64:
		return writeUint64(v.Uint(), w)
	case reflect.Struct:
		return writeStruct(v, w)
	case reflect.Array, reflect.Slice:
		return writeSlice(v, w)
	case reflect.Pointer:
		if v.IsZero() {
			return fmt.Errorf("cannot encode a nil pointer")
		}
		return writeValue(v.Elem(), w)
	default:
		return fmt.Errorf("cannot encode value of type %s", kind)
	}
}

func writeBool(v bool, w io.Writer) error {
	var x byte = 0
	if v {
		x = 1
	}
	_, err := w.Write([]byte{x})
	return err
}

func writeInt8(n int8, w io.Writer) error {
	_, err := w.Write([]byte{byte(n)})
	return err
}

func writeUint8(n uint8, w io.Writer) error {
	_, err := w.Write([]byte{byte(n)})
	return err
}

func writeInt16(n int16, w io.Writer) error {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], uint16(n))
	_, err := w.Write(b[:])
	return err
}

func writeUint16(n uint16, w io.Writer) error {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func writeInt32(n int32, w io.Writer) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(n))
	_, err := w.Write(b[:])
	return err
}

func writeUint32(n uint32, w io.Writer) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func writeInt64(n int64, w io.Writer) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(n))
	_, err := w.Write(b[:])
	return err
}

func writeUint64(n uint64, w io.Writer) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	_, err := w.Write(b[:])
	return err
}

func writeSlice(v reflect.Value, w io.Writer) error {
	n := v.Len()
	if n == 0 {
		return nil
	}
	if v.Index(0).Kind() == reflect.Uint8 {
		_, err := w.Write(v.Bytes())
		return err
	}
	for i := 0; i < n; i++ {
		err := writeValue(v.Index(i), w)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeStruct(v reflect.Value, w io.Writer) error {
	t := v.Type()
	n := v.NumField()
	for i := 0; i < n; i++ {
		fv := v.Field(i)
		tag := t.Field(i).Tag.Get("wbf")
		var err error
		switch tag {
		case "u8size":
			err = writeSliceWithSize(fv, w, writeUint8)
		case "u16size":
			err = writeSliceWithSize(fv, w, writeUint16)
		case "u32size":
			err = writeSliceWithSize(fv, w, writeUint32)
		case "optional":
			err = writeOptional(fv, w)
		case "":
			err = writeValue(fv, w)
		default:
			err = fmt.Errorf("no handler for wbf tag %q", tag)
		}
		if err != nil {
			return fmt.Errorf("cannot write field %s: %w", t.Field(i).Name, err)
		}
	}
	return nil
}

func writeOptional(v reflect.Value, w io.Writer) error {
	if v.Kind() != reflect.Pointer {
		return errors.New("optional cannot be applied to non-pointer")
	}
	exists := !v.IsZero()
	err := writeBool(exists, w)
	if err != nil {
		return err
	}
	if exists {
		return writeValue(v, w)
	}
	return nil
}

func writeSliceWithSize[T interface{ uint8 | uint16 | uint32 }](
	v reflect.Value,
	w io.Writer,
	writeUint func(T, io.Writer) error,
) error {
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		size := T(v.Len())
		err := writeUint(size, w)
		if err != nil {
			return err
		}
		return writeValue(v, w)
	default:
		return errors.New("u8size/u16size/u32size cannot be applied to non-slice value")
	}
}

func Unmarshal(v any, b []byte) error {
	r := bytes.NewReader(b)
	err := ReadValue(v, r)
	if err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("cannot unmarshal value: remaining bytes")
	}
	return nil
}

func ReadValue(v any, r io.Reader) error {
	pointer := reflect.ValueOf(v)
	if pointer.Kind() != reflect.Pointer {
		return fmt.Errorf("cannot unmarshal into a non-pointer")
	}
	if pointer.IsZero() {
		return fmt.Errorf("cannot unmarshal into a nil pointer")
	}
	return readValue(pointer.Elem(), r)
}

func MustUnmarshal(v any, b []byte) {
	err := Unmarshal(v, b)
	if err != nil {
		panic(err)
	}
}

func readValue(v reflect.Value, r io.Reader) error {
	if _, ok := v.Type().MethodByName("WBFRead"); ok {
		v.Set(reflect.New(v.Elem().Type()))
		r := v.MethodByName("WBFRead").Call([]reflect.Value{reflect.ValueOf(r)})
		if !r[0].IsZero() {
			return r[0].Interface().(error)
		}
		return nil
	}
	kind := v.Kind()
	var err error
	switch kind {
	case reflect.Bool:
		var ret bool
		ret, err = readBool(r)
		if err != nil {
			return err
		}
		v.SetBool(ret)
	case reflect.Int8:
		var ret int8
		ret, err = readInt8(r)
		if err != nil {
			return err
		}
		v.SetInt(int64(ret))
	case reflect.Uint8:
		var ret uint8
		ret, err = readUint8(r)
		if err != nil {
			return err
		}
		v.SetUint(uint64(ret))
	case reflect.Int16:
		var ret int16
		ret, err = readInt16(r)
		if err != nil {
			return err
		}
		v.SetInt(int64(ret))
	case reflect.Uint16:
		var ret uint16
		ret, err = readUint16(r)
		if err != nil {
			return err
		}
		v.SetUint(uint64(ret))
	case reflect.Int32:
		var ret int32
		ret, err = readInt32(r)
		if err != nil {
			return err
		}
		v.SetInt(int64(ret))
	case reflect.Uint32:
		var ret uint32
		ret, err = readUint32(r)
		if err != nil {
			return err
		}
		v.SetUint(uint64(ret))
	case reflect.Int64:
		var ret int64
		ret, err = readInt64(r)
		if err != nil {
			return err
		}
		v.SetInt(ret)
	case reflect.Uint64:
		var ret uint64
		ret, err = readUint64(r)
		if err != nil {
			return err
		}
		v.SetUint(ret)
	case reflect.Struct:
		return readStruct(v, r)
	case reflect.Array:
		return readSlice(v.Slice(0, v.Len()), r)
	case reflect.Slice:
		return readSlice(v, r)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		return readValue(v.Elem(), r)
	default:
		return fmt.Errorf("cannot decode a value of type %s", kind)
	}
	return nil
}

func readBool(r io.Reader) (bool, error) {
	var b [1]byte
	_, err := r.Read(b[:])
	if err != nil {
		return false, fmt.Errorf("cannot decode bool value: %w", err)
	}
	return b[0] != 0, nil
}

func readInt8(r io.Reader) (int8, error) {
	var b [1]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode int8 value: %w", err)
	}
	return int8(b[0]), nil
}

func readUint8(r io.Reader) (uint8, error) {
	var b [1]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode uint8 value: %w", err)
	}
	return b[0], nil
}

func readInt16(r io.Reader) (int16, error) {
	var b [2]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode int16 value: %w", err)
	}
	return int16(binary.LittleEndian.Uint16(b[:])), nil
}

func readUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode uint16 value: %w", err)
	}
	return binary.LittleEndian.Uint16(b[:]), nil
}

func readInt32(r io.Reader) (int32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode int32 value: %w", err)
	}
	return int32(binary.LittleEndian.Uint32(b[:])), nil
}

func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode uint32 value: %w", err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readInt64(r io.Reader) (int64, error) {
	var b [8]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode int64 value: %w", err)
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
}

func readUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("cannot decode uint64 value: %w", err)
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func readStruct(v reflect.Value, r io.Reader) error {
	t := v.Type()
	n := v.NumField()
	for i := 0; i < n; i++ {
		fv := v.Field(i)
		tag := t.Field(i).Tag.Get("wbf")
		var err error
		switch tag {
		case "u8size":
			err = readSliceWithSize(fv, r, readUint8)
		case "u16size":
			err = readSliceWithSize(fv, r, readUint16)
		case "u32size":
			err = readSliceWithSize(fv, r, readUint32)
		case "optional":
			err = readOptional(fv, r)
		case "":
			err = readValue(fv, r)
		default:
			err = fmt.Errorf("no handler for wbf tag %q", tag)
		}
		if err != nil {
			return fmt.Errorf("cannot read field %s: %w", t.Field(i).Name, err)
		}
	}
	return nil
}

func readOptional(v reflect.Value, r io.Reader) error {
	if v.Kind() != reflect.Pointer {
		return errors.New("optional cannot be applied to non-pointer")
	}
	exists, err := readBool(r)
	if err != nil {
		return err
	}
	if !exists {
		if !v.IsZero() {
			v.Set(reflect.Zero(v.Type()))
		}
		return nil
	}
	newValue := reflect.New(v.Type().Elem())
	v.Set(newValue)
	return readValue(v, r)
}

func readSliceWithSize[T interface{ uint8 | uint16 | uint32 }](
	v reflect.Value,
	r io.Reader,
	readUint func(io.Reader) (T, error),
) error {
	n, err := readUint(r)
	if err != nil {
		return err
	}
	v.Set(reflect.MakeSlice(v.Type(), int(n), int(n)))
	return readSlice(v, r)
}

func readSlice(v reflect.Value, r io.Reader) error {
	n := v.Len()
	if n == 0 {
		return nil
	}
	if v.Index(0).Kind() == reflect.Uint8 {
		b := make([]byte, n)
		_, err := r.Read(b)
		if err != nil {
			return fmt.Errorf("cannot decode byte slice: %w", err)
		}
		copied := reflect.Copy(v, reflect.ValueOf(b))
		if copied != n {
			panic("inconsistency")
		}
		return nil
	}
	for i := 0; i < n; i++ {
		err := readValue(v.Index(i), r)
		if err != nil {
			return err
		}
	}
	return nil
}
