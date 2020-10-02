package main

import (
	"fmt"

	"bufio"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := scanner.Text()
		suffix, _ := publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, &publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: publicsuffix.DefaultRule})
		fmt.Printf("%s %s\n", domain[:len(domain)-len(suffix)], suffix)
	}
}
