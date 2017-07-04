package main

import (
	"flag"
	"fmt"
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
	fmt.Println("ICMPTX Proxy at", flag.Arg(0))

	t := icmptxutil.NewIcmptx()

	if *isServer {
		fmt.Println("Running as server mode...")
		t.SetSource(proxyAddr)
		t.SetMode(*isServer)
	} else if *isClient {
		fmt.Println("Runnging as client mode...")
		t.SetAddr(proxyAddr)
		t.SetID(os.Getpid() & 0xffff)
	}

	t.Run()
}
