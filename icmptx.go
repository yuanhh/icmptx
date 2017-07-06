package main

import (
	"flag"
	"fmt"
	"os"

	"icmptx/icmptxutil"
)

func main() {

	proxy := flag.Bool("s", false, "running icmptx as server")
	client := flag.Bool("c", false, "running icmptx as client")
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	proxyAddr := flag.Arg(0)
	fmt.Println("ICMPTX Proxy at", flag.Arg(0))

	t := icmptxutil.NewIcmptx()

	if *proxy {
		fmt.Println("Running as server mode...")
		t.SetSource(proxyAddr)
		t.SetProxy(*proxy)
	} else if *client {
		fmt.Println("Runnging as client mode...")
		t.SetAddr(proxyAddr)
		t.SetID(os.Getpid() & 0xffff)
	}

	t.Run()
}
