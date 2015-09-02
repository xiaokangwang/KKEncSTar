package main

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/codahale/chacha20"
	"github.com/golang/snappy"
	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"url"
)

func progd_forword(ar cmdoptS) {

	//create metadata leveldb

	db, err := leveldb.OpenFile(ar.in_dir+"/md", nil)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

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

	_, _, nd = LimitedSizeWriteToFilei.Finialize()

	FileHash := new([]byte, 64)
	HashWriter.Read(FileHash)

	var poly1305sum [16]byte
	var poly1305sum_key [32]byte

	copy(poly1305sum_key[:], poly1305key)

	poly1305.Sum(&poly1305sum, FileHash, &poly1305sum_key)

	err = db.Put([]byte("poly1305sum"), poly1305sum[:], nil)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	bb := new(bytes.Buffer)
	binary.Write(bb, binary.LittleEndian, nd)

	err = db.Put([]byte("packagesum"), bb.Bytes(), nil)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	//we won't use it anymore
	db.Close()

	//finially we call par2 to compute reconstruction data
	if ar.parrate != 0 {
		path, err := exec.LookPath("par2")
		if err != nil {
			fmt.Println("Unable to whereis par2, reconstruction data compute was ignored:" + err.Error())
		}

		DirIf, _ := os.Open(ar.out_dir)
		DirIfs, _ := DirIf.Readdirnames()

		cmd := exec.Command("par2", "c", "-a"+"mdpp", "-r"+strconv.Itoa(ar.parrate), "-v", "--", DirIfs...)
		Absp, _ := filepath.Abs(ar.out_dir)
		cmd.Dir = Absp
		err = cmd.Start()
		if err != nil {
			fmt.Println("Unable to exec par2, reconstruction data compute was ignored:" + err.Error())
		}
		err = cmd.Wait()
		if err != nil {
			fmt.Println("par2 was finished unsuccessfully, reconstruction data compute was ignored(or failed):" + err.Error())
		}
	}

	fmt.Println("Hash: %x", FileHash)
	fmt.Println("Key: %s", ar.secret_key)

}

func progd_reverse(ar cmdoptS) {

	if ar.parrate != 0 { //we do not care the actual number
		path, err := exec.LookPath("par2")
		if err != nil {
			fmt.Println("Unable to whereis par2, metadata reconstruction was ignored:" + err.Error())
		}

		DirIf, _ := os.Open(ar.out_dir)
		DirIfs, _ := DirIf.Readdirnames()

		cmd := exec.Command("par2", "r", "-a"+"mdpp", "-v", "--", "md")
		Absp, _ := filepath.Abs(ar.out_dir)
		cmd.Dir = Absp
		err = cmd.Start()
		if err != nil {
			fmt.Println("Unable to exec par2, metadata reconstruction data compute was ignored:" + err.Error())
		}
		err = cmd.Wait()
		if err != nil {
			fmt.Println("par2 was finished unsuccessfully, metadata reconstruction data compute was ignored(or failed):" + err.Error())
		}
	}

	//Open metadata leveldb
	db, err := leveldb.OpenFile(ar.in_dir+"/md", nil)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	ndb, err := db.Get([]byte("packagesum"), nil)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	var nd int64
	var not_going bool

	missing_file := make([]string, 0, 25)
	all_file := make([]string, 0, 25)

	binary.Read(ndb, binary.LittleEndian, nd)

	for cfn := range nd {
		cnnn := fmt.Sprintf(ar.in_dir+"/df%X", cfn)
		append(all_file, fmt.Sprintf("df%X", cfn))

		if _, err := os.Stat(cnnn); err != nil {
			if ar.parrate == 0 {
				not_going = true
				append(missing_file, fmt.Sprintf("df%X", cfn))
			} else {

				//touch the missing file so that par2 will try to recover this
				cfnd, err := os.Create(cnnn)

				if err != nil {
					fmt.Println(err.Error())
					os.Exit(-1)
				}

				cfnd.Close()

				append(missing_file, fmt.Sprintf("df%X", cfn))

			}
		}
	}

	if len(missing_file) != 0 {
		if ar.parrate == 0 {
			fmt.Println("%d file missing")

			for cf := range len(missing_file) {
				fmt.Println(cf)
			}

			fmt.Println("Failed to reverse operate as there is file missing.")
			os.Exit(-1)

		} else {
			fmt.Println("%d file missing, but reconstruction by par2 underway.")

			for cf := range len(missing_file) {
				fmt.Println(missing_file[cf])
			}
		}
	}

	data_reconstruction_unsuccessful := true

	if ar.parrate != 0 { //we do not care the actual number
		path, err := exec.LookPath("par2")
		if err != nil {
			fmt.Println("Unable to whereis par2, data reconstruction was ignored:" + err.Error())
		}

		cmd := exec.Command("par2", "r", "-a"+"mdpp", "-v", "--", all_file...)
		Absp, _ := filepath.Abs(ar.out_dir)
		cmd.Dir = Absp
		err = cmd.Start()
		if err != nil {
			fmt.Println("Unable to exec par2, metadata reconstruction was ignored:" + err.Error())
		}
		err = cmd.Wait()
		if err != nil {
			fmt.Println("par2 was finished unsuccessfully, data reconstruction was ignored(or failed):" + err.Error())
		} else {
			data_reconstruction_unsuccessful = false
		}
	}

	if ar.parrate != 0 && data_reconstruction_unsuccessful {
		fmt.Println("operation failed: unable to reconstruct.")
		fmt.Println("If data were correct, remove parrate might do.")

		for dfnow := range len(missing_file) {
			os.Remove(ar.in_dir + "/" + missing_file)
		}

		os.Exit(-1)
	}

	//now we do the actual job

	nonce, err := db.Get([]byte("nonce"), nil)
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

	//set up stream

	var LimitedSizeReadFromi LimitedSizeReadFrom

	LimitedSizeReadFromi.TargetPatten = ar.in_dir + "/df%X"

	cryptos, err := chacha20.NewXChaCha(xchachakey, nonce)

	HashWriter := sha3.NewShake256()

	Tread := io.TeeReader(LimitedSizeReadFromi, HashWriter)

	DataReader := NewDecryptedReader(Tread, cryptos)

	DeCompressedStream = snappy.NewReader(DataReader)

	TarStream := tar.NewReader(DeCompressedStream)

	for {
		hdr, err := TarStream.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			log.Fatalln(err)
		}
		filenamex := hdr.Name
		if !IsPathAllowed(hdr.Name) {
			filenamex = url.QueryEscape(hdr.Name)
		}

		cfhd, err := os.Create(ar.out_dir + "/" + filenamex)

		if err != nil {
			log.Fatalln(err)
		}

		_, err := io.Copy(cfhd, TarStream)

		if err != nil {
			log.Fatalln(err)
		}

		cfhd.Close()

	}

	LimitedSizeReadFromi.Finialize()

	FileHash := new([]byte, 64)
	HashWriter.Read(FileHash)
	fmt.Println("Hash: %x", FileHash)

	var poly1305sum [16]byte
	var poly1305sum_key [32]byte
	poly1305sums, err := db.Get([]byte("poly1305sum"), nil)

	copy(poly1305sum[:], poly1305sums)
	copy(poly1305sum_key[:], poly1305key)

	iscorrect := poly1305.Verify(&poly1305sum, FileHash, &poly1305sum_key)

	if iscorrect == true {
		fmt.Println("Correct File data")
		os.Exit(0)
	} else {
		fmt.Println("File data is't match!")
		os.Exit(-2)
	}

}

func IsPathAllowed(p string) bool {
	if filepath.IsAbs(p) == true {
		return false
	}

	if strings.Contains(filepath.ToSlash(filepath.Clean(p)), "../") {
		return false
	}

	return true

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
