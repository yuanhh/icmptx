package main

import (
	"flag"
	"os"

	"icmptx/icmptxutil"
)

func main() {

	isServer := flag.Bool("s", false, "running icmptx as server")
	isClient := flag.Bool("c", false, "running icmptx as client")
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	proxyAddr := flag.Arg(0)

	t := icmptxutil.NewIcmptx()

	if *isServer {
		t.SetSource(proxyAddr)
		t.SetMode(*isServer)
	} else if *isClient {
		t.SetAddr(proxyAddr)
		t.SetID(os.Getpid() & 0xffff)
	}

	t.Run()
}
