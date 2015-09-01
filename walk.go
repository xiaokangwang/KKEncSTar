package main

import (
	"archive/tar"
	"errors"
	"github.com/codahale/chacha20"
	"github.com/golang/snappy"
	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
	"path/filepath"
)

func progd_forword(ar cmdoptS) {

	//create metadata leveldb

	db, err := leveldb.OpenFile(ar.in_dir+"/md", nil)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	defer db.Close()

	//generate crypto nonce

	nonce := GenerateRandomBytes(24)

	//store it

	err = db.Put([]byte("nonce"), nonce, nil)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	//calc key

	keyhasher := sha3.NewShake256()

	keyhasher.Write(nonce)
	keyhasher.Write([]byte(ar.secret_key))

	xchachakey := make([]byte, 32)
	keyhasher.Read(xchachakey)

	poly1305key := make([]byte, 32)
	keyhasher.Read(poly1305key)

	//init stream

	var LimitedSizeWriteToFilei LimitedSizeWriteToFile
	LimitedSizeWriteToFilei.TargetPatten = ar.in_dir + "/df%X"

	cryptos, err := chacha20.NewXChaCha(xchachakey, nonce)

	HashWriter := sha3.NewShake256()

	CyDWriter := io.MultiWriter(LimitedSizeWriteToFilei, HashWriter)

	Data_writer := NewEncryptedWriter(cryptos, CyDWriter)

	CompressedStream = snappy.NewWriter(Data_writer)

	TarStream := tar.NewWriter(CompressedStream)

	GenFileList(ar.in_dir)

	for id := range rfi {
		filedes, err := os.Open(ar.in_dir + "/" + igni[id])
		if err != nil {
			fmt.Println("Failed to open file " + igni[id] + ":" + err.Error())
		}
		hdr := &tar.Header{
			Name: rfi[filename],
			Mode: 0600,
			Size: filedes.Stat().Size(),
		}

		if err := TarStream.WriteHeader(hdr); err != nil {
			log.Fatalln(err)
		}

		_, err = io.Copy(TarStream, filedes)

		if err != nil {
			fmt.Println("Failed to open file " + igni[id] + ":" + err.Error())
		}

		filedes.Close()

	}

}

func GenFileList(s string) {

	igni = len(s) + 1

	filepath.Walk(s+"/", swalk)

}

var igni, CurrentFn int

var rfi map[int]string

func swalk(path string, info os.FileInfo, err error) error {

	if !info.IsDir() {
		rfi[CurrentFn] = path[igni:]
		CurrentFn += 1
	}

}

func NewEncryptedWriter(target io.Writer, encryptFunc cipher.Stream) EncryptedWriter {
	var EncryptedWriteri EncryptedWriter
	EncryptedWriteri.target = target
	EncryptedWriteri.encryptFunc = encryptFunc
	return EncryptedWriteri

}

type EncryptedWriter struct {
	io.Writer
	target      io.Writer
	encryptFunc cipher.Stream
}

func (lf *EncryptedWriter) Write(p []byte) (n int, err error) {
	inputBuffer := make([]byte, len(p))
	lf.encryptFunc.XORKeyStream[inputBuffer:p]
	return lf.target.Write(inputBuffer)

}

func NewDecryptedReader(target io.Reader, decryptFunc cipher.Stream) DecryptedReader {
	var DecryptedReaderi EncryptedReader
	DecryptedReaderi.target = target
	DecryptedReaderi.decryptFunc = decryptFunc
	return DecryptedReaderi

}

type DecryptedReader struct {
	io.Reader
	target      io.Reader
	decryptFunc cipher.Stream
}

func (lf *DecryptedReader) Read(p []byte) (n int, err error) {
	inputBuffer := make([]byte, len(p))
	lf.decryptFunc.XORKeyStream[inputBuffer:p]
	return lf.target.Read(inputBuffer)

}

type LimitedSizeWriteToFile struct {
	BytesPerFile int64
	io.Writer
	TargetPatten string
	cfd          *os.File //current file descripter
	cfn          int64    //currnet file number
	cfnd         int64    //current file byte written
	nd           int64    //bytes written
}

func (lf *LimitedSizeWriteToFile) Write(p []byte) (n int, err error) {

	if lf.TargetPatten == "" {
		return 0, errors.New("LimitedSizeWriteToFile: no patten set")
	}

	//create a file if first call
	if lf.nd == 0 {
		fn := fmt.Sprintf(lf.TargetPatten, cfn)
		lf.fd, err = os.Create(fn)
		if err != nil {
			return 0, err
		}
	}

	if len(p) >= BytesPerFile {
		return 0, errors.New("LimitedSizeWriteToFile: BytesPerFile <= single write")
	}

	if len(p)+cfnd >= BytesPerFile {
		cfd.Close()
		cfn += 1
		cfnd = 0
		lf.fd, err = os.Create(fn)
		if err != nil {
			return 0, err
		}
	}

	n, err := lf.cfd.Write(p)

	lf.cfnd += n
	lf.nd += n

	return n, err

}

func (lf *LimitedSizeWriteToFile) Finialize() (FileCreated, LastSize, TotalBytesWritten int64) {
	lf.cfd.Close()
	return cfn, cfnd, nd

}

type LimitedSizeReadFrom struct {
	io.Reader
	TargetPatten string
	cfd          *os.File //current file descripter
	cfn          int64    //currnet file number
	cfnd         int64    //current file byte readden
	nd           int64    //bytes readden
}

func (lf *LimitedSizeReadFrom) Read(p []byte) (n int, err error) {
	if lf.TargetPatten == "" {
		return 0, errors.New("LimitedSizeWriteToFile: no patten set")
	}

	//Open a file if first call
	if lf.nd == 0 {
		fn := fmt.Sprintf(lf.TargetPatten, cfn)
		lf.fd, err = os.OpenFile(fn)
		if err != nil {
			return 0, err
		}
	}

	n, err := lf.cfd.Read(p)

	if err == io.EOF {
		fn := fmt.Sprintf(lf.TargetPatten, cfn+1)
		lf.fd, err = os.OpenFile(fn)
		if err != nil {

			if os.IsNotExist(err) {
				return 0, io.EOF
			} else {
				return 0, err
			}
			cfn += 1
			cfnd = 0
		}
	}
	return n, err

}

func (lf *LimitedSizeReadFrom) Finialize() (FileCreated, LastSize, TotalBytesWritten int64) {
	lf.cfd.Close()
	return cfn, cfnd, nd

}
