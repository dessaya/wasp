package actors

// Result represents the result of a computation that may have failed.
type Result[T any] struct {
	Ok  *T
	Err error
}

func NewResult[T any](v T, err error) Result[T] {
	if err != nil {
		return NewResultErr[T](err)
	}
	return NewResultOk(v)
}

func NewResultOk[T any](v T) Result[T] {
	return Result[T]{Ok: &v, Err: nil}
}

func NewResultErr[T any](err error) Result[T] {
	return Result[T]{Ok: nil, Err: err}
}

func (r Result[T]) IsOk() bool {
	return r.Err == nil
}
