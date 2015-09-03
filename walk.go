package main

import (
	"archive/tar"
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/codahale/chacha20"
	"github.com/golang/snappy"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const const_Mbyte int64 = 1024 * 1024
const const_Kbyte int64 = 1024

func progd_forword(ar cmdoptS) {

	//create metadata leveldb

	dbi, err := bolt.Open(ar.out_dir+"/md", 0600, nil)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	tx, err := dbi.Begin(true)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	defer tx.Rollback()
	db, err := tx.CreateBucket([]byte("Ketv1"))

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	//generate crypto nonce

	nonce, _ := GenerateRandomBytes(24)

	//store it

	err = db.Put([]byte("nonce"), nonce)
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
	LimitedSizeWriteToFilei.InitNow()
	LimitedSizeWriteToFilei.TargetPatten = ar.out_dir + "/df%X"
	if !ar.div_unitk {
		LimitedSizeWriteToFilei.BytesPerFile = int64(ar.div_at) * const_Mbyte
	} else {
		LimitedSizeWriteToFilei.BytesPerFile = int64(ar.div_at) * const_Kbyte
	}

	cryptos, err := chacha20.NewXChaCha(xchachakey, nonce)

	HashWriter := sha3.NewShake256()

	CyDWriter := io.MultiWriter(LimitedSizeWriteToFilei, HashWriter)

	Data_writer := NewEncryptedWriter(cryptos, CyDWriter)

	CompressedStream := snappy.NewWriter(Data_writer)

	TarStream := tar.NewWriter(CompressedStream)

	GenFileList(ar.in_dir)

	for id := range rfi {
		filedes, err := os.Open(ar.in_dir + "/" + rfi[id])
		if err != nil {
			fmt.Println("Failed to open file " + rfi[id] + ":" + err.Error())
		}
		filein, _ := filedes.Stat()
		hdr := &tar.Header{
			Name: rfi[id],
			Mode: 0600,
			Size: filein.Size(),
		}

		if err := TarStream.WriteHeader(hdr); err != nil {
			log.Fatalln(err)
		}

		_, err = io.Copy(TarStream, filedes)

		if err != nil {
			fmt.Println("Failed to Write file " + rfi[id] + ":" + err.Error())
		}

		filedes.Close()

	}

	if err := TarStream.Close(); err != nil {
		log.Fatalln(err)
	}

	_, _, nd := LimitedSizeWriteToFilei.Finialize()

	FileHash := make([]byte, 64)
	HashWriter.Read(FileHash)

	var poly1305sum [16]byte
	var poly1305sum_key [32]byte

	copy(poly1305sum_key[:], poly1305key)

	poly1305.Sum(&poly1305sum, FileHash, &poly1305sum_key)

	err = db.Put([]byte("poly1305sum"), poly1305sum[:])
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	bb := new(bytes.Buffer)
	binary.Write(bb, binary.LittleEndian, nd)

	err = db.Put([]byte("packagesum"), bb.Bytes())
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	//we won't use it anymore
	if err := tx.Commit(); err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	dbi.Close()

	//finially we call par2 to compute reconstruction data
	if ar.parrate != 0 {
		_, err := exec.LookPath("par2")
		if err != nil {
			fmt.Println("Unable to whereis par2, reconstruction data compute was ignored:" + err.Error())
		}

		DirIf, _ := os.Open(ar.out_dir)
		DirIfs, _ := DirIf.Readdirnames(-1)

		cmdargs := []string{"c", "-a", "mdpp", "-r" + strconv.Itoa(ar.parrate), "-v", "--"}
		cmdargs = append(cmdargs, DirIfs...)

		cmd := exec.Command("par2", cmdargs...)
		cmd.Stdout = os.Stdout
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

	fmt.Printf("Hash: %x\n", FileHash)
	fmt.Printf("Key: %s\n", ar.secret_key)

}

func progd_reverse(ar cmdoptS) {

	if ar.parrate != 0 { //we do not care the actual number
		_, err := exec.LookPath("par2")
		if err != nil {
			fmt.Println("Unable to whereis par2, metadata reconstruction was ignored:" + err.Error())
		}

		cmd := exec.Command("par2", "r", "-a"+"mdpp", "-v", "--", "md")
		cmd.Stdout = os.Stdout
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
	dbi, err := bolt.Open(ar.in_dir+"/md", 0600, nil)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	tx, err := dbi.Begin(false)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	defer tx.Rollback()
	db := tx.Bucket([]byte("Ketv1"))

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	ndb := db.Get([]byte("packagesum"))

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	var nd int64

	missing_file := make([]string, 0, 25)
	all_file := make([]string, 0, 25)

	binary.Read(bytes.NewBuffer(ndb), binary.LittleEndian, nd)
	var cfn int64
	for cfn <= nd {
		cnnn := fmt.Sprintf(ar.in_dir+"/df%X", cfn)
		all_file = append(all_file, fmt.Sprintf("df%X", cfn))

		if _, err := os.Stat(cnnn); err != nil {
			if ar.parrate == 0 {
				missing_file = append(missing_file, fmt.Sprintf("df%X", cfn))
			} else {

				//touch the missing file so that par2 will try to recover this
				cfnd, err := os.Create(cnnn)

				if err != nil {
					fmt.Println(err.Error())
					os.Exit(-1)
				}

				cfnd.Close()

				missing_file = append(missing_file, fmt.Sprintf("df%X", cfn))

			}
		}
		cfn++
	}

	if len(missing_file) != 0 {
		if ar.parrate == 0 {
			fmt.Println("%d file missing", len(missing_file))

			for cf := range missing_file {
				fmt.Println(cf)
			}

			fmt.Println("Failed to reverse operate as there is file missing.")
			os.Exit(-1)

		} else {
			fmt.Println("%d file missing, but reconstruction by par2 underway.")

			for cf := range missing_file {
				fmt.Println(cf)
			}
		}
	}

	data_reconstruction_unsuccessful := true

	if ar.parrate != 0 { //we do not care the actual number
		_, err := exec.LookPath("par2")
		if err != nil {
			fmt.Println("Unable to whereis par2, data reconstruction was ignored:" + err.Error())
		}

		cmdargs := []string{"r", "-a" + "mdpp", "-v", "--"}

		cmdargs = append(cmdargs, all_file...)

		cmd := exec.Command("par2", cmdargs...)
		cmd.Stdout = os.Stdout
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

		for cf := range missing_file {
			os.Remove(fmt.Sprint("%s/%s", ar.in_dir, cf))
		}

		os.Exit(-1)
	}

	//now we do the actual job

	nonce := db.Get([]byte("nonce"))
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

	LimitedSizeReadFromi.InitNow()

	LimitedSizeReadFromi.TargetPatten = ar.in_dir + "/df%X"

	cryptos, err := chacha20.NewXChaCha(xchachakey, nonce)

	HashWriter := sha3.NewShake256()

	Tread := io.TeeReader(LimitedSizeReadFromi, HashWriter)

	DataReader := NewDecryptedReader(Tread, cryptos)

	DeCompressedStream := snappy.NewReader(DataReader)

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

		dirc := filepath.Dir(ar.out_dir + "/" + filenamex)
		os.MkdirAll(dirc, 0700)

		cfhd, err := os.Create(ar.out_dir + "/" + filenamex)

		if err != nil {
			log.Fatalln(err)
		}

		_, err = io.Copy(cfhd, TarStream)

		if err != nil {
			log.Fatalln(err)
		}

		cfhd.Close()

	}

	LimitedSizeReadFromi.Finialize()

	FileHash := make([]byte, 64)
	HashWriter.Read(FileHash)
	fmt.Printf("Hash: %x\n", FileHash)

	var poly1305sum [16]byte
	var poly1305sum_key [32]byte
	poly1305sums := db.Get([]byte("poly1305sum"))

	copy(poly1305sum[:], poly1305sums)
	copy(poly1305sum_key[:], poly1305key)

	iscorrect := poly1305.Verify(&poly1305sum, FileHash, &poly1305sum_key)

	dbi.Close()

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

	rfi = make(map[int]string)

	filepath.Walk(s+"/", swalk)

}

var igni, CurrentFn int

var rfi map[int]string

func swalk(path string, info os.FileInfo, err error) error {

	if !info.IsDir() {
		rfi[CurrentFn] = path[igni:]
		CurrentFn += 1
	}
	return nil
}

func NewEncryptedWriter(encryptFunc cipher.Stream, target io.Writer) EncryptedWriter {
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

func (lf EncryptedWriter) Write(p []byte) (n int, err error) {
	inputBuffer := make([]byte, len(p))
	lf.encryptFunc.XORKeyStream(inputBuffer, p)
	return lf.target.Write(inputBuffer)

}

func NewDecryptedReader(target io.Reader, decryptFunc cipher.Stream) DecryptedReader {
	var DecryptedReaderi DecryptedReader
	DecryptedReaderi.target = target
	DecryptedReaderi.decryptFunc = decryptFunc
	return DecryptedReaderi

}

type DecryptedReader struct {
	io.Reader
	target      io.Reader
	decryptFunc cipher.Stream
}

func (lf DecryptedReader) Read(p []byte) (n int, err error) {
	inputBuffer := make([]byte, len(p))
	n, err = lf.target.Read(inputBuffer)
	lf.decryptFunc.XORKeyStream(p, inputBuffer)
	return n, err

}

type LimitedSizeWriteToFile struct {
	BytesPerFile int64
	io.Writer
	TargetPatten string
	cfd          **os.File //current file descripter
	cfn          *int64    //currnet file number
	cfnd         *int64    //current file byte written
	nd           *int64    //bytes written
}

func (lf *LimitedSizeWriteToFile) InitNow() {
	lf.cfn = new(int64)
	lf.cfnd = new(int64)
	lf.nd = new(int64)
	lf.cfd = new(*os.File)
}

func (lf LimitedSizeWriteToFile) Write(p []byte) (n int, err error) {

	if lf.TargetPatten == "" {
		return 0, errors.New("LimitedSizeWriteToFile: no patten set")
	}

	//create a file if first call
	if *lf.nd == int64(0) {
		fn := fmt.Sprintf(lf.TargetPatten, *lf.cfn)
		*lf.cfd, err = os.Create(fn)
		if err != nil {
			return 0, err
		}
	}

	if int64(len(p)) >= lf.BytesPerFile {
		return 0, errors.New("LimitedSizeWriteToFile: BytesPerFile <= single write")
	}

	if int64(len(p))+*lf.cfnd >= lf.BytesPerFile {
		(**lf.cfd).Close()
		*lf.cfn += 1
		*lf.cfnd = 0
		fn := fmt.Sprintf(lf.TargetPatten, *lf.cfn)
		*lf.cfd, err = os.Create(fn)
		if err != nil {
			return 0, err
		}
	}

	n, err = (**lf.cfd).Write(p)

	*lf.cfnd += int64(n)
	*lf.nd += int64(n)

	return n, err

}

func (lf *LimitedSizeWriteToFile) Finialize() (FileCreated, LastSize, TotalBytesWritten int64) {
	(**lf.cfd).Close()
	return *lf.cfn, *lf.cfnd, *lf.nd

}

type LimitedSizeReadFrom struct {
	io.Reader
	TargetPatten string
	cfd          **os.File //current file descripter
	cfn          *int64    //currnet file number
	cfnd         *int64    //current file byte readden
	nd           *int64    //bytes readden
}

func (lf *LimitedSizeReadFrom) InitNow() {
	lf.cfn = new(int64)
	lf.cfnd = new(int64)
	lf.nd = new(int64)
	lf.cfd = new(*os.File)
}

func (lf LimitedSizeReadFrom) Read(p []byte) (n int, err error) {
	if lf.TargetPatten == "" {
		return 0, errors.New("LimitedSizeWriteToFile: no patten set")
	}

	//Open a file if first call
	if *lf.nd == int64(0) {
		fn := fmt.Sprintf(lf.TargetPatten, *lf.cfn)
		*lf.cfd, err = os.Open(fn)
		if err != nil {
			return 0, err
		}
	}

	n, err = (**lf.cfd).Read(p)

	if err == io.EOF {
		fn := fmt.Sprintf(lf.TargetPatten, *lf.cfn+1)
		*lf.cfd, err = os.Open(fn)
		if err != nil {

			if os.IsNotExist(err) {
				return 0, io.EOF
			} else {
				return 0, err
			}
		}
		*lf.cfn += 1
		*lf.cfnd = 0
		return lf.Read(p)
	}
	*lf.nd += int64(n)
	*lf.cfnd += int64(n)
	return n, err

}

func (lf *LimitedSizeReadFrom) Finialize() (FileCreated, LastSize, TotalBytesWritten int64) {
	(**lf.cfd).Close()
	return *lf.cfn, *lf.cfnd, *lf.nd

}
