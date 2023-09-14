package main

import (
	"github.com/guoyk93/dummycert"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"time"
)

func main() {
	suites := map[string]string{
		"rootca": "Root Certificate Authority",
		"middle": "Middle Certificate Authority",
		"server": "Server Certificate",
		"client": "Client Certificate",
	}

	cmdCreate := &cli.Command{
		Name:  "create-chain",
		Usage: "create a certificate chain",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "dir",
				Usage:       "output directory",
				Value:       ".",
				DefaultText: "current directory",
			},
			&cli.IntFlag{
				Name:        "bits",
				Usage:       "bit size of private key, one of 1024, 2048, 4096 for RSA",
				Value:       2048,
				DefaultText: "2048",
			},
		},
		Action: func(c *cli.Context) error {
			opts := &dummycert.CreateChainOptions{
				Dir:  c.String("dir"),
				Bits: c.Int("bits"),
			}
			for name := range suites {
				var bo *dummycert.KeyPairOptions
				switch name {
				case "rootca":
					bo = &opts.RootCA
				case "middle":
					bo = &opts.Middle
				case "server":
					bo = &opts.Server
				case "client":
					bo = &opts.Client
				}
				bo.CommonName = c.String(name + "-common-name")
				bo.NotBefore = *c.Timestamp(name + "-not-before")
				bo.NotAfter = *c.Timestamp(name + "-not-after")
				bo.DNSNames = c.StringSlice(name + "-dns-name")
			}
			return dummycert.CreateChain(*opts)
		},
	}

	var (
		timeLayout = "2006-01-02 15:04:05"
		timeBase   = time.Now()
	)

	for name, displayName := range suites {
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.StringFlag{
			Name:     name + "-common-name",
			Category: name,
			Usage:    "common name for " + name,
			Value:    "Dummycert - " + displayName,
		})
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.StringSliceFlag{
			Name:     name + "-dns-name",
			Category: name,
			Usage:    "dns name for " + name,
		})
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.TimestampFlag{
			Name:        name + "-not-before",
			Category:    name,
			Usage:       "not before for " + name,
			Layout:      timeLayout,
			Value:       cli.NewTimestamp(timeBase),
			DefaultText: "now",
		})
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.TimestampFlag{
			Name:        name + "-not-after",
			Category:    name,
			Usage:       "not after for " + name,
			Layout:      timeLayout,
			Value:       cli.NewTimestamp(timeBase.AddDate(1, 0, 0)),
			DefaultText: "1 year later",
		})
	}

	app := cli.NewApp()
	app.Usage = "A tool to create a full cert chain for debug purpose (including root CA, middle CA, server leaf, client leaf)"
	app.Name = "dummycert"
	app.Authors = []*cli.Author{
		{
			Name:  "GUO YANKE",
			Email: "hi@guoyk.xyz",
		},
	}
	app.Commands = append(app.Commands, cmdCreate)

	if err := app.Run(os.Args); err != nil {
		log.Println("exited with error:", err.Error())
		os.Exit(1)
	}
}
