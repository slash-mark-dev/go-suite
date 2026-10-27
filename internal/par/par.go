// Package par runs work in parallel with a bounded number of goroutines.
package par

import (
	"context"
	"sync"
)

// Map applies fn to every item using at most n goroutines and returns the
// results in input order. errs[i] is fn's error for items[i].
func Map[T, R any](ctx context.Context, n int, items []T, fn func(context.Context, T) (R, error)) ([]R, []error) {
	if n <= 0 {
		n = 8
	}
	res := make([]R, len(items))
	errs := make([]error, len(items))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, it := range items {
		if ctx.Err() != nil {
			errs[i] = ctx.Err()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, it T) {
			defer wg.Done()
			defer func() { <-sem }()
			res[i], errs[i] = fn(ctx, it)
		}(i, it)
	}
	wg.Wait()
	return res, errs
}

// Each runs fn for every item using at most n goroutines.
func Each[T any](ctx context.Context, n int, items []T, fn func(context.Context, T)) {
	Map(ctx, n, items, func(ctx context.Context, t T) (struct{}, error) {
		fn(ctx, t)
		return struct{}{}, nil
	})
}

// FirstErr returns the first non-nil error.
func FirstErr(errs []error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
