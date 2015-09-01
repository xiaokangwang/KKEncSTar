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
}

//define and parse commandline arg
func argpg() cmdoptS {
	var cmdopt cmdoptS
	flag.IntVar(&cmdopt.div_at, "ds", -1, "Define what size should we keep our data block below. Unset means no max size.")
	flag.BoolVar(&cmdopt.div_unitk, "duk", false, "The unit of ds, if set to true is KByte or it will be MByte.")
	flag.StringVar(&cmdopt.in_dir, "id", "in", "The dir to be progress.")
	flag.StringVar(&cmdopt.out_dir, "od", "out", "The dir output go to.")
	flag.StringVar(&cmdopt.secret_key, "s", "", "The password used to seal file, if it is empty, we will generate one for you.")
	flag.BoolVar(&cmdopt.reverse, "r", false, "Reverse operation.")

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

	if ar.reverse == true && secret_key == "" {
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
	return GenerateRandomString(32)
}

func forword(ar cmdoptS) {

}

func reverse(ar cmdoptS) {

}

func main() {

	cmdopt := argpg()

	if argCheck() != true {
		os.Exit(-1)
	}

	if cmdopt.secret_key == "" {
		cmdopt.secret_key = GenKey()
	}

	//create output folder

	err := os.Mkdir(cmdopt.out_dir)

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
