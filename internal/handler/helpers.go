package handler

import (
	"context"
	"strconv"
	"time"
)

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}

func now() time.Time {
	return time.Now()
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
