package scan

import "errors"

func mkfifo(string) error { return errors.New("FIFOs are not available on Windows") }
