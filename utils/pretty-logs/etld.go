package main

import (
	"fmt"

	"bufio"
	"golang.org/x/net/publicsuffix"
	"os"
)

func main() {

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := scanner.Text()
		TLD, _ := publicsuffix.PublicSuffix(domain)
		eTLD, _ := publicsuffix.EffectiveTLDPlusOne(domain)

		if len(TLD) > 10 {
			eTLD = TLD
		}

		fmt.Printf("\033[2m%s\033[0m%s\n", domain[:len(domain)-len(eTLD)], eTLD)
	}
}
