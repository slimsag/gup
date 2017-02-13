package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/kr/binarydist"
	"github.com/slimsag/gup/guputil"
)

var commands = map[string]*flag.FlagSet{}

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: gup [flags] [command] [arguments]

commands:
	bundle: create a new gup patch bundle
	patch: apply a gup patch bundle
	genkey: generates an ECDSA P256 public and private key pair.

other commands:
	bsdiff: create a new bsdiff patch file
	bspatch: apply a bsdiff patch file

`)
	}

	commands["bundle"] = flag.NewFlagSet("gup bundle", flag.ExitOnError)
	commands["bundle"].Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: gup bundle [flags] [old.exe] new.exe

overview:
  bundle creates one of two types of bundle patch files:

  1. A binary diff file, which transitions from [old.exe] to [new.exe] using
     the bsdiff algorithm.
  2. A binary replacement file, which transitions from [old.exe] to [new.exe]
     by literally copying [new.exe] directly.

  In all cases, the produced bundle file will have an ECDSA P256 bin.signature
  of the [new.exe] signed by the specified private_key.pem. This signature is
  stored inside the gup bundle file and is used upon extraction to verify the
  authorship of the binary. Additionally, the SHA256 checksum of the binary
  patch or binary replacement file is also stored in the bundle for
  verification of binary integrity upon extraction.

flags:
  -private-key="private_key.pem"

  -tag="main" specifies a tag to use for the bundle, e.g. "main", "beta",
              "alpha", "wow".

  -os="" specifies the OS suffix to use for the bundle, e.g. "linux", "darwin",
         "windows". Defaults to build.Default.GOOS

  -arch="" specifies the arch suffix to use for the bundle, e.g. "amd64",
           "i386", etc. Defaults to build.Default.GOARCH

  -replacement=false specifies whether or not to generate a full-binary
                     replacement bundle instead of a binary diff bundle. This
                     should be used if e.g. the entire binary has changed, or
                     if the chain of updates has grown quite large.

`)
	}
	bundleReplacement := commands["bundle"].Bool("replacement", false, "generate a full-binary replacement bundle instead of a binary diff")
	bundlePrivateKey := commands["bundle"].String("private-key", "private_key.pem", "the private key file")
	bundleTag := commands["bundle"].String("tag", "main", "tag to use for the bundle")
	bundleOS := commands["bundle"].String("os", "", "os to use for the bundle")
	bundleArch := commands["bundle"].String("arch", "", "arch to use for the bundle")

	commands["patch"] = flag.NewFlagSet("gup patch", flag.ExitOnError)
	commands["patch"].Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: gup patch [flags] old.exe new.exe

flags:
  -public-key="public_key.pem"

  -tag="main" specifies the tag to look for in the index. See 'gup bundle' for
              details.

  -single="" specifies a single patch.tgz file to apply, instead of using the
             default behavior (looking at the index.json and patching to the
             latest version).

`)
	}
	patchSingle := commands["patch"].String("single", "", "a specific patch.tgz file to apply")
	patchPublicKey := commands["patch"].String("public-key", "public_key.pem", "the public key file")
	patchTag := commands["patch"].String("tag", "main", "tag to look for in the index")

	commands["bsdiff"] = flag.NewFlagSet("gup bsdiff", flag.ExitOnError)
	commands["bsdiff"].Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: gup bsdiff old.exe new.exe out.patch

`)
	}

	commands["bspatch"] = flag.NewFlagSet("gup bspatch", flag.ExitOnError)
	commands["bspatch"].Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: gup bspatch old.exe new.exe in.patch

`)
	}

	commands["genkey"] = flag.NewFlagSet("gup genkey", flag.ExitOnError)
	commands["genkey"].Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: gup genkey

flags:
  -private-key="private_key.pem"
  -public-key="public_key.pem"

`)
	}
	genkeyPrivateKey := commands["genkey"].String("private-key", "private_key.pem", "the private key file")
	genkeyPublicKey := commands["genkey"].String("public-key", "public_key.pem", "the public key file")

	handleErr := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(2)
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid command\n")
		flag.Usage()
		os.Exit(2)
	}
	if err := cmd.Parse(os.Args[2:]); err != nil {
		log.Fatal(err)
	}

	parsePrivateKey := func(name string) *ecdsa.PrivateKey {
		keyData, err := ioutil.ReadFile(name)
		handleErr(err)

		// Decode and parse the private key.
		block, _ := pem.Decode(keyData)
		if block == nil {
			handleErr(errors.New("failed to parse public key"))
		}
		if block.Type != "EC PRIVATE KEY" {
			handleErr(errors.New("expected private key to have block type EC PRIVATE KEY"))
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		handleErr(err)
		return key
	}

	switch os.Args[1] {
	case "bundle":
		if len(cmd.Args()) != 2 && len(cmd.Args()) != 1 {
			cmd.Usage()
			os.Exit(2)
		}
		key := parsePrivateKey(*bundlePrivateKey)

		tag := guputil.Tag(*bundleTag, *bundleOS, *bundleArch)
		switch len(cmd.Args()) {
		case 1:
			// TODO(slimsag): optionally parametrize
			if _, err := os.Stat("gup/index.json"); !os.IsNotExist(err) {
				handleErr(errors.New("gup replace: may only omit [old.exe] when index.json doesn't exist"))
			}

			new, err := os.Open(cmd.Arg(0))
			handleErr(err)
			defer new.Close()

			outFile := filepath.Join("gup", guputil.UpdateFilename(tag, 0)) // TODO(slimsag): optionally parametrize?
			out, err := os.Create(outFile)
			handleErr(err)
			defer out.Close()

			bundle, err := guputil.Diff(key, nil, new, out)
			handleErr(err)

			fmt.Println("wrote replacement patch bundle:", outFile)

			index := &guputil.Index{
				Tags: map[string]*guputil.IndexVersions{
					tag: &guputil.IndexVersions{
						List: []guputil.IndexVersion{{
							From:        bundle.Checksum,
							To:          bundle.Checksum,
							Replacement: true,
						}},
					},
				},
			}

			indexData, err := json.MarshalIndent(index, "", "  ")
			handleErr(err)
			err = ioutil.WriteFile("gup/index.json", indexData, 0666) // TODO(slimsag): optionally parametrize
			handleErr(err)
			fmt.Println("wrote index: gup/index.json")
			fmt.Println("")
			fmt.Println(bundle)

		case 2:
			var index *guputil.Index
			indexFile, err := os.Open("gup/index.json") // TODO(slimsag): optionally parametrize
			handleErr(err)
			err = json.NewDecoder(indexFile).Decode(&index)
			handleErr(err)

			old, err := ioutil.ReadFile(cmd.Arg(0))
			handleErr(err)

			new, err := os.Open(cmd.Arg(1))
			handleErr(err)
			defer new.Close()

			versionIndex := len(index.Tags[tag].List)
			outFile := filepath.Join("gup", guputil.UpdateFilename(tag, versionIndex)) // TODO(slimsag): optionally parametrize?
			out, err := os.Create(outFile)
			handleErr(err)
			defer out.Close()

			var bundle *guputil.BundleInfo
			if *bundleReplacement {
				bundle, err = guputil.Diff(key, nil, new, out)
				handleErr(err)
				fmt.Println("wrote replacement patch bundle:", outFile)
			} else {
				bundle, err = guputil.Diff(key, bytes.NewReader(old), new, out)
				handleErr(err)
				fmt.Println("wrote diff patch bundle:", outFile)
			}

			oldChecksum, err := guputil.Checksum(bytes.NewReader(old))
			handleErr(err)
			if oldChecksum == bundle.Checksum {
				handleErr(errors.New("error updating index; [old] and [new] are identical"))
			}
			index.Tags[tag].List = append(index.Tags[tag].List, guputil.IndexVersion{
				From:        oldChecksum,
				To:          bundle.Checksum,
				Replacement: *bundleReplacement,
			})

			indexData, err := json.MarshalIndent(index, "", "  ")
			handleErr(err)
			err = ioutil.WriteFile("gup/index.json", indexData, 0666) // TODO(slimsag): optionally parametrize
			handleErr(err)
			fmt.Println("updated index: gup/index.json")
			fmt.Println("")
			fmt.Println(bundle)

		default:
			panic("never here")
		}

	case "patch":
		if len(cmd.Args()) != 2 {
			cmd.Usage()
			os.Exit(2)
		}
		keyData, err := ioutil.ReadFile(*patchPublicKey)
		handleErr(err)
		pubKey, err := guputil.ParsePublicKey(keyData)
		handleErr(err)

		old, err := ioutil.ReadFile(cmd.Arg(0))
		handleErr(err)

		outFile := cmd.Arg(1)
		new, err := os.Create(outFile)
		handleErr(err)
		defer new.Close()

		if *patchSingle != "" {
			// Applying a single patch.
			in, err := os.Open(cmd.Arg(2))
			handleErr(err)
			defer in.Close()

			bundle, err := guputil.Patch(pubKey, bytes.NewReader(old), new, in)
			handleErr(err)
			fmt.Println("wrote", outFile)
			fmt.Println("")
			fmt.Println(bundle)
		} else {
			// Patching to latest.
			var index *guputil.Index
			indexFile, err := os.Open("gup/index.json") // TODO(slimsag): optionally parametrize
			handleErr(err)
			err = json.NewDecoder(indexFile).Decode(&index)
			handleErr(err)

			tag := guputil.ExpandTag(*patchTag)

			for {
				oldChecksum, err := guputil.Checksum(bytes.NewReader(old))
				handleErr(err)
				version, versionIndex := index.Tags[tag].FindNextVersion(oldChecksum)
				if version == nil {
					log.Println("at latest version")
					break
				}
				updateFile := filepath.Join("gup", guputil.UpdateFilename(tag, versionIndex))
				in, err := os.Open(updateFile) // TODO(slimsag): make relative to index.json
				handleErr(err)

				var newBuf bytes.Buffer
				_, err = guputil.Patch(pubKey, bytes.NewReader(old), &newBuf, in)
				handleErr(err)
				old = newBuf.Bytes()
				desc := "incremental"
				if version.Replacement {
					desc = "replacement"
				}
				log.Printf("applied %s update %s", desc, updateFile)

				in.Close()
			}
		}

	case "bsdiff":
		if len(cmd.Args()) != 3 {
			cmd.Usage()
			os.Exit(2)
		}
		old, err := os.Open(cmd.Arg(0))
		handleErr(err)
		defer old.Close()

		new, err := os.Open(cmd.Arg(1))
		handleErr(err)
		defer new.Close()

		out, err := os.Create(cmd.Arg(2))
		handleErr(err)
		defer out.Close()

		err = binarydist.Diff(old, new, out)
		handleErr(err)

	case "bspatch":
		if len(cmd.Args()) != 3 {
			cmd.Usage()
			os.Exit(2)
		}
		old, err := os.Open(cmd.Arg(0))
		handleErr(err)
		defer old.Close()

		new, err := os.Create(cmd.Arg(1))
		handleErr(err)
		defer new.Close()

		out, err := os.Open(cmd.Arg(2))
		handleErr(err)
		defer out.Close()

		err = binarydist.Patch(old, new, out)
		handleErr(err)

	case "genkey":
		if len(cmd.Args()) != 0 {
			cmd.Usage()
			os.Exit(2)
		}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		handleErr(err)

		{
			// Don't overwrite the file if it already exists.
			outFile := *genkeyPrivateKey
			out, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
			handleErr(err)
			defer out.Close()

			derBytes, err := x509.MarshalECPrivateKey(key)
			handleErr(err)

			err = pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
			handleErr(err)
			fmt.Println("# wrote", outFile)
		}

		{
			// Don't overwrite the file if it already exists.
			outFile := *genkeyPublicKey
			out, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
			handleErr(err)
			defer out.Close()

			derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			handleErr(err)

			var buf bytes.Buffer
			err = pem.Encode(io.MultiWriter(out, &buf), &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
			handleErr(err)
			fmt.Println("# wrote", outFile)

			fmt.Println("Note: You may copy+paste the following public key into your Go program:")
			fmt.Println("")
			fmt.Printf("gup.Config.PublicKey = %q\n", buf.String())
			fmt.Println("")
		}

	default:
		panic("never here")
	}
}
