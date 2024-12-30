package main

import (
	"log"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/yankeguo/dummycert"
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
				var co *dummycert.CertificateOptions
				switch name {
				case "rootca":
					co = &opts.RootCA
				case "middle":
					co = &opts.Middle
				case "server":
					co = &opts.Server
				case "client":
					co = &opts.Client
				}
				co.SerialNumber = c.Int64(name + "-serial-number")
				co.CommonName = c.String(name + "-common-name")
				co.NotBefore = *c.Timestamp(name + "-not-before")
				co.NotAfter = *c.Timestamp(name + "-not-after")
				co.DNSNames = c.StringSlice(name + "-dns-name")
				co.IPAddresses = c.StringSlice(name + "-ip")
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
			Value:    "DummyCert - " + displayName,
		})
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.Int64Flag{
			Name:        name + "-serial-number",
			Category:    name,
			Usage:       "serial number for " + name,
			Value:       timeBase.UnixNano(),
			DefaultText: "current time unix nano",
		})
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.StringSliceFlag{
			Name:     name + "-dns-name",
			Category: name,
			Usage:    "dns name for " + name,
		})
		cmdCreate.Flags = append(cmdCreate.Flags, &cli.StringSliceFlag{
			Name:     name + "-ip",
			Category: name,
			Usage:    "ip address for " + name,
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
			Email: "hi@yankeguo.com",
		},
	}
	app.Commands = append(app.Commands, cmdCreate)

	if err := app.Run(os.Args); err != nil {
		log.Println("exited with error:", err.Error())
		os.Exit(1)
	}
}
