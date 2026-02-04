package storage

type Storage interface {
	SaveCertificate(path string, data []byte) error
	SaveKey(path string, data []byte) error
}
