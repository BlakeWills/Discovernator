package dns

import (
	"encoding/binary"
	"fmt"
)

type Message struct {
	Header MessageHeader
}

type MessageHeader struct {
	Id                     uint16
	Response               bool
	OpCode                 byte
	AuthoritativeAnswer    bool
	Truncated              bool
	RecursionDesired       bool
	RecursionAvailable     bool
	ResponseCode           byte
	QuestionCount          uint16
	AnswerCount            uint16
	NameserverCount        uint16
	AdditionalRecordsCount uint16
}

func Parse(packet []byte) Message {
	offset := 0

	id, offset := getUint16(packet, offset)
	flags, offset := getUint16(packet, offset)

	fmt.Printf("%016b\n", flags)

	qr := (flags>>(16-1))&1 == 1
	op := (flags >> (16 - 5)) & 0xF
	aa := (flags>>(16-6))&1 == 1
	tc := (flags>>(16-7))&1 == 1
	rd := (flags>>(16-8))&1 == 1
	ra := (flags>>(16-6))&1 == 1
	rcode := flags & 0xF

	qdCount, offset := getUint16(packet, offset)
	anCount, offset := getUint16(packet, offset)
	nsCount, offset := getUint16(packet, offset)
	arCount, offset := getUint16(packet, offset)

	header := MessageHeader{
		Id:                     id,
		Response:               qr,
		OpCode:                 byte(op),
		AuthoritativeAnswer:    aa,
		Truncated:              tc,
		RecursionDesired:       rd,
		RecursionAvailable:     ra,
		ResponseCode:           byte(rcode),
		QuestionCount:          qdCount,
		AnswerCount:            anCount,
		NameserverCount:        nsCount,
		AdditionalRecordsCount: arCount}

	return Message{Header: header}
}

func getUint16(data []byte, offset int) (uint16, int) {
	return binary.BigEndian.Uint16(data[offset:]), offset + 2
}
