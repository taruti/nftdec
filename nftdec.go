package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/taruti/native"
	"os"
	"strings"
)

func main() {
	for _, a := range os.Args[1:] {
		e := dec(a)
		if e != nil {
			fmt.Println(e)
			return
		}
		fmt.Printf("=================================================================\n")
		fmt.Printf("=================================================================\n")
		fmt.Printf("=================================================================\n")
	}
}

func dec(s string) error {
	s = strings.NewReplacer(`x`, ``, `\`, ``, `"`, ``).Replace(s)
	bs, e := hex.DecodeString(s)
	if e != nil {
		return e
	}
	p := native.NewParser(bs)
	return ph(p)
}

func ph(p *native.Parser) error {
	var w0, w1, w2 uint16
	var l0, l1, l2 uint32
	var b0, b1, b2 uint8
	p.U32(&l0).U16(&w0).U16(&w1).U32(&l1).U32(&l2).Byte(&b0).Byte(&b1).U16(&w2)
	fmt.Printf("=================================================================\n")
	fmt.Printf("Total len: %08X data bytes: %d\n", l0, l0-20)
	fmt.Printf("Op:        %04X %s\n", w0, u2s(ms[:], int(w0&nfnlopmask)))
	fmt.Printf("Type:      %04X\n", w1)
	fmt.Printf("Seq:       %08X\n", l1)
	fmt.Printf("Zero:      %08X\n", l2)
	fmt.Printf("Family:    %02X\n", b0)
	fmt.Printf("Version:   %02X\n", b1)
	fmt.Printf("Resource:  %04X\n", w2)
	_, _, _ = w2, b1, b2
	if w0 == 16 {
		for !p.AtEnd() {
			e := ph(p)
			if e != nil {
				return e
			}
		}
	} else {
		var cl = uint32(20)
		for !p.AtEnd() && cl < l0 {
			var l, t uint16
			var raw []byte
			p.U16(&l).U16(&t)
			cl += lpa(l)
			fmt.Printf("-----------------------------------------------------------------\n")
			fmt.Printf("Len:       %04X\n", l)
			fmt.Printf("Typ:       %04X\n", t)
			switch t {
			default:
				if l < 4 {
					return errors.New("Too short attr")
				}
				p.NBytes(int(l)-4, &raw)
				fmt.Printf("Raw:       %X\n", raw)
			}
			p.Align(4)
		}
	}
	return nil
}

func lpa(rl uint16) uint32 {
	if rl&3 != 0 {
		rl = (rl &^ 3) + 4
	}
	return uint32(rl)
}

func u2s(s []string, i int) string {
	if len(s) <= i {
		return fmt.Sprint(i)
	}
	return s[i]
}

const nfnl_SUBSYS_NFTABLES = 10

var nfnlopmask = ^(uint16(nfnl_SUBSYS_NFTABLES) << 8)

const (
	nft_MSG_NEWTABLE = iota
	nft_MSG_GETTABLE
	nft_MSG_DELTABLE
	nft_MSG_NEWCHAIN
	nft_MSG_GETCHAIN
	nft_MSG_DELCHAIN
	nft_MSG_NEWRULE
	nft_MSG_GETRULE
	nft_MSG_DELRULE
	nft_MSG_NEWSET
	nft_MSG_GETSET
	nft_MSG_DELSET
	nft_MSG_NEWSETELEM
	nft_MSG_GETSETELEM
	nft_MSG_DELSETELEM
	nft_MSG_MAX
)

var ms = [...]string{
	nft_MSG_NEWTABLE:   "MSG_NEWTABLE",
	nft_MSG_GETTABLE:   "MSG_GETTABLE",
	nft_MSG_DELTABLE:   "MSG_DELTABLE",
	nft_MSG_NEWCHAIN:   "MSG_NEWCHAIN",
	nft_MSG_GETCHAIN:   "MSG_GETCHAIN",
	nft_MSG_DELCHAIN:   "MSG_DELCHAIN",
	nft_MSG_NEWRULE:    "MSG_NEWRULE",
	nft_MSG_GETRULE:    "MSG_GETRULE",
	nft_MSG_DELRULE:    "MSG_DELRULE",
	nft_MSG_NEWSET:     "MSG_NEWSET",
	nft_MSG_GETSET:     "MSG_GETSET",
	nft_MSG_DELSET:     "MSG_DELSET",
	nft_MSG_NEWSETELEM: "MSG_NEWSETELEM",
	nft_MSG_GETSETELEM: "MSG_GETSETELEM",
	nft_MSG_DELSETELEM: "MSG_DELSETELEM",
	//	nft_MSG_MAX:        "MSG_MAX",
	16: "NFNL_MSG_BATCH_BEGIN",
	17: "NFNL_MSG_BATCH_END",
}

const (
	NFNL_SUBSYS_NONE = iota
	NFNL_SUBSYS_CTNETLINK
	NFNL_SUBSYS_CTNETLINK_EXP
	NFNL_SUBSYS_QUEUE
	NFNL_SUBSYS_ULOG
	NFNL_SUBSYS_OSF
	NFNL_SUBSYS_IPSET
	NFNL_SUBSYS_ACCT
	NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NFNL_SUBSYS_CTHELPER
	NFNL_SUBSYS_NFTABLES
	NFNL_SUBSYS_NFT_COMPAT
	NFNL_SUBSYS_COUNT
)

var subsys = [...]string{
	NFNL_SUBSYS_NONE:              "NFNL_SUBSYS_NONE",
	NFNL_SUBSYS_CTNETLINK:         "NFNL_SUBSYS_CTNETLINK",
	NFNL_SUBSYS_CTNETLINK_EXP:     "NFNL_SUBSYS_CTNETLINK_EXP",
	NFNL_SUBSYS_QUEUE:             "NFNL_SUBSYS_QUEUE",
	NFNL_SUBSYS_ULOG:              "NFNL_SUBSYS_ULOG",
	NFNL_SUBSYS_OSF:               "NFNL_SUBSYS_OSF",
	NFNL_SUBSYS_IPSET:             "NFNL_SUBSYS_IPSET",
	NFNL_SUBSYS_ACCT:              "NFNL_SUBSYS_ACCT",
	NFNL_SUBSYS_CTNETLINK_TIMEOUT: "NFNL_SUBSYS_CTNETLINK_TIMEOUT",
	NFNL_SUBSYS_CTHELPER:          "NFNL_SUBSYS_CTHELPER",
	NFNL_SUBSYS_NFTABLES:          "NFNL_SUBSYS_NFTABLES",
	NFNL_SUBSYS_NFT_COMPAT:        "NFNL_SUBSYS_NFT_COMPAT",
	NFNL_SUBSYS_COUNT:             "NFNL_SUBSYS_COUNT",
}
