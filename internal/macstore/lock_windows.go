package macstore

import (
	"errors"
	"os"
)

func lockFile(*os.File) error { return errors.New("Mac Store state is unsupported on Windows") }
