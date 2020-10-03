package main

import (
	"fmt"
	"strings"

	"bufio"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := scanner.Text()
		suffix, _ := publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, &publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: publicsuffix.DefaultRule})
		if strings.HasSuffix(suffix,"in-addr.arpa"){
			suffix="in-addr.arpa"
		}
		fmt.Printf("%s\t%s\n", domain[:len(domain)-len(suffix)], suffix)
	}
}
