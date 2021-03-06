package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

type cmdoptS struct {
	div_at     int
	div_unitk  bool
	in_dir     string
	out_dir    string
	secret_key string
	reverse    bool
	parrate    int
}

//define and parse commandline arg
func argpg() cmdoptS {
	var cmdopt cmdoptS
	flag.IntVar(&cmdopt.div_at, "ds", 24, "Define what size should we keep our data block below. Unset means 24.")
	flag.BoolVar(&cmdopt.div_unitk, "duk", false, "The unit of ds, if set to true is KByte or it will be MByte.")
	flag.StringVar(&cmdopt.in_dir, "id", "in", "The dir to be progress.")
	flag.StringVar(&cmdopt.out_dir, "od", "out", "The dir output go to.")
	flag.StringVar(&cmdopt.secret_key, "s", "", "The password used to seal file, if it is empty, we will generate one for you.")
	flag.BoolVar(&cmdopt.reverse, "r", false, "Reverse operation.")
	flag.IntVar(&cmdopt.parrate, "p", 0, "Define Par2 reconstruction rate  in %%. Unset means no reconstruction data.")

	//Do it!
	flag.Parse()
	return cmdopt
}

func dir_exists(path string) bool {
	d, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if !d.IsDir() {
		return false
	}
	return true
}

func argCheck(ar cmdoptS) bool {
	if !dir_exists(ar.in_dir) {
		fmt.Println("in_dir isn't exist")
		return false
	}

	if dir_exists(ar.out_dir) {
		fmt.Println("out_dir exist")
		return false
	}

	if ar.reverse == true && ar.secret_key == "" {
		fmt.Println("Reverse but no key")
		return false
	}

	return true

}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func GenKey() string {
	s, _ := GenerateRandomString(32)
	return s
}

func forword(ar cmdoptS) {
	progd_forword(ar)
}

func reverse(ar cmdoptS) {
	progd_reverse(ar)
}

func main() {

	cmdopt := argpg()

	if argCheck(cmdopt) != true {
		os.Exit(-1)
	}

	if cmdopt.secret_key == "" {
		cmdopt.secret_key = GenKey()
	}

	//create output folder

	err := os.Mkdir(cmdopt.out_dir, 0700)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	//Walk in source folder

	if !cmdopt.reverse {
		forword(cmdopt)
	} else {
		reverse(cmdopt)
	}

}
