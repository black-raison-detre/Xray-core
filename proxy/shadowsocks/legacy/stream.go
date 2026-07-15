package legacy

import (
	"crypto/cipher"
	"fmt"
	"io"
)

// Writer prefixes the IV once and preserves stream state across writes.
type Writer struct {
	writer io.Writer
	stream cipher.Stream
}

func (c *Cipher) NewWriter(writer io.Writer) (*Writer, []byte, error) {
	iv, err := c.GenerateIV()
	if err != nil {
		return nil, nil, err
	}
	stream, err := c.NewEncrypter(iv)
	if err != nil {
		return nil, nil, err
	}
	if err := writeAll(writer, iv); err != nil {
		return nil, nil, fmt.Errorf("write %s IV: %w", c.method.Name, err)
	}
	return &Writer{writer: writer, stream: stream}, iv, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	ciphertext := make([]byte, len(p))
	w.stream.XORKeyStream(ciphertext, p)
	if err := writeAll(w.writer, ciphertext); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Reader consumes the IV once and preserves stream state across reads.
type Reader struct {
	reader io.Reader
	stream cipher.Stream
}

func (c *Cipher) NewReader(reader io.Reader) (*Reader, []byte, error) {
	iv := make([]byte, c.method.IVSize)
	if _, err := io.ReadFull(reader, iv); err != nil {
		return nil, nil, fmt.Errorf("read %s IV: %w", c.method.Name, err)
	}
	stream, err := c.NewDecrypter(iv)
	if err != nil {
		return nil, nil, err
	}
	return &Reader{reader: reader, stream: stream}, iv, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func writeAll(writer io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := writer.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
