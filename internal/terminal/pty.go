package terminal

import (
	"io"
	"sync"
)

type PTY struct {
	reader io.ReadCloser
	writer io.WriteCloser
	resize func(cols, rows uint16) error
	wait   func() error
	close  func() error
	once   sync.Once
}

func (p *PTY) Read(buf []byte) (int, error) {
	return p.reader.Read(buf)
}

func (p *PTY) Write(buf []byte) (int, error) {
	return p.writer.Write(buf)
}

func (p *PTY) Resize(cols, rows uint16) error {
	if p.resize == nil {
		return nil
	}
	return p.resize(cols, rows)
}

func (p *PTY) Wait() error {
	if p.wait == nil {
		return nil
	}
	return p.wait()
}

func (p *PTY) Close() error {
	var err error
	p.once.Do(func() {
		if p.close != nil {
			err = p.close()
			return
		}
		if p.reader != nil {
			_ = p.reader.Close()
		}
		if p.writer != nil {
			_ = p.writer.Close()
		}
	})
	return err
}
