package storage

import "os"

type FileSystemStorage struct{}

func (f *FileSystemStorage) SaveCertificate(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func (f *FileSystemStorage) SaveKey(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
