package ipmi

import (
	"fmt"

	"github.com/kuiwang02/bmc/pkg/iana"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Message represents an IPMI message, specified in 12.4 of the v1.5 spec and
// 13.8 of the v2.0 spec. This is the layer within v1.5 sessions, and within
// v2.0 sessions with the "IPMI" payload type. It carries addressing information
// and command identification for processing of the next layer, which is either
// a request or response.
//
// Wire format of a request (offsets in square brackets):
//
//  1. [0] Responder address (1 byte)
//     - LSB determines the type: 0 for slave address, 1 for software ID.
//     - Remaining 7 bits hold the value.
//     - Always 0x20 when the BMC is the responder (slave address 16).
//  2. [1] Network Function Code (most-significant 6 bits)
//     - Always even for a request.
//  3. Responder's LUN (least-significant 2 bits)
//     - 00 for BMC commands.
//  4. [2] Checksum (1 byte)
//  5. [3] Requester's Address (1 byte)
//     - Same as for responder address.
//     - Again, always 0x20 when the BMC is the requester (slave address 16).
//  6. [4] Sequence Number (most-significant 6 bits)
//     - Generated by requester, mirrored in response.
//  7. Requester's LUN (least-significant 2 bits)
//     - 00 for BMC commands.
//  8. [5] Command (1 byte)
//     - e.g. Get System GUID is 0x37
//  9. [6] Request Data
//     - If a response, the first byte is the completion code.
//     - If NetFn is Group/OEM, next byte is body code, else if NetFn is OEM,
//     next 3 bytes are the OEM's enterprise number.
//  10. [last] Checksum from [3] onwards (1 byte)
//
// This struct has been generalised to cater for both requests and responses; in
// the case of a request, Remote* fields correspond to responder attributes and
// Local* fields correspond to requester attributes, and vice-versa in the case
// of responses. Note that Local* is therefore not always the remote console.
// The BMC is also perfectly entitled to send request messages. Requests and
// responses were combined to reduce code duplication - the only field that
// differs between them is the existence of a completion code in responses.
type Message struct {
	layers.BaseLayer

	// Operation encapsulates the network function and command fields.
	Operation

	// RemoteAddress is the slave address or software ID of the responder if
	// this is a request, or requester if this is a response. The
	// least-significant bit dictates the type. This will always be 0x20 when
	// the BMC is the responder (slave address 0x10).
	RemoteAddress Address

	// RemoteLUN is the logical unit number of the responder if this is a
	// request, or requester if this is a response. In practice, this will
	// almost always be 0 (BMC commands).
	RemoteLUN LUN

	// Checksum1 is a checksum over the two bytes that make up the  remote
	// address, remote LUN and function code fields. This will be calculated
	// automatically if FixChecksums is set to true in the serialise options. If
	// this checksum is incorrect, the BMC drops the packet.
	Checksum1 uint8

	// LocalAddress is the slave address or software ID of the responder if this
	// is a response, or requester if this is a request.
	LocalAddress Address

	// LocalLUN is the logical unit number of the requester if this is a
	// request, or responder if this is a response.
	LocalLUN LUN

	// Sequence is the sequence number of the message. This is used for matching
	// up responses with requests. It is a 6-bit uint on the wire.
	Sequence uint8

	// CompletionCode indicates whether a request message completed
	// successfully. This will be 0 if the message is a request. This is in the
	// message layer as it dictates whether the data layer can be decoded. A
	// side effect is that response layers are all one byte shorter than the
	// specification would indicate, and handling for this value does not have
	// to be done in every one of their decode methods - indeed, it means we
	// don't have to implement DecodingLayer for commands that return only a
	// completion code, like Close Session.
	CompletionCode

	// Checksum2 is a checksum over the local address, local LUN, sequence
	// number and command. If this checksum is incorrect, the BMC drops the
	// packet.
	Checksum2 uint8
}

func (*Message) LayerType() gopacket.LayerType {
	return LayerTypeMessage
}

func (m *Message) CanDecode() gopacket.LayerClass {
	return m.LayerType()
}

func (m *Message) NextLayerType() gopacket.LayerType {
	// If there is a non-zero completion code, the next layer is always
	// LayerTypePayload. Fundamentally, a non-zero completion code is not a
	// *decode* error. It's still a valid packet. The spec says additional
	// fields after such a completion code have device-specific content, so it
	// is useless for us to make assumptions, and we'd probably just get false
	// positive errors. "Typically, a responder will truncate all fields
	// following a non-zero completion code and addressing extension bytes"
	// (i.e. parse the completion code and body code/EN, then check the
	// completion code and if it's non-zero don't go any further). We don't even
	// bother with SetTruncated() to ease the error handling and let gopacket
	// expose the raw bytes, if any.
	if m.CompletionCode != CompletionCodeNormal {
		return gopacket.LayerTypePayload
	}
	return m.Operation.NextLayerType()
}

func (m *Message) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 7 {
		df.SetTruncated()
		return fmt.Errorf("must be at least 7 bytes, got %v", len(data))
	}

	m.RemoteAddress = Address(data[0])
	m.Function = NetworkFunction(data[1] >> 2)
	m.RemoteLUN = LUN(data[1] & 0x3)
	m.Checksum1 = uint8(data[2])
	if want := checksum(data[:2]); m.Checksum1 != want {
		return fmt.Errorf("invalid checksum1: got %v, want %v", m.Checksum1,
			want)
	}

	m.LocalAddress = Address(data[3])
	m.Sequence = uint8(data[4] >> 2)
	m.LocalLUN = LUN(data[4] & 0x3)
	m.Command = CommandNumber(data[5])

	// last checksum is always last byte
	m.Checksum2 = uint8(data[len(data)-1])
	if want := checksum(data[3 : len(data)-1]); m.Checksum2 != want {
		return fmt.Errorf("invalid checksum2: got %v, want %v", m.Checksum2,
			want)
	}

	if m.Function.IsRequest() {
		return m.decodeRequest(data, df)
	}
	return m.decodeResponse(data, df)
}

func (m *Message) decodeRequest(data []byte, df gopacket.DecodeFeedback) error {
	m.CompletionCode = 0
	return m.decodeDataHeader(data, 6, df)
}

func (m *Message) decodeResponse(data []byte, df gopacket.DecodeFeedback) error {
	m.CompletionCode = CompletionCode(data[6]) // already validated min length of 7
	return m.decodeDataHeader(data, 7, df)
}

func (m *Message) decodeDataHeader(data []byte, start int, df gopacket.DecodeFeedback) error {
	consumed, err := m.decodeSpecialNetFns(data[start:len(data)-1], df)
	if err != nil {
		return err
	}
	m.BaseLayer.Contents = data[:start+consumed]
	m.BaseLayer.Payload = data[start+consumed : len(data)-1] // remove trailing checksum; may be empty
	return nil
}

func (m *Message) decodeSpecialNetFns(data []byte, df gopacket.DecodeFeedback) (int, error) {
	m.Body = 0
	m.Enterprise = 0
	switch m.Function {
	case NetworkFunctionGroupReq, NetworkFunctionGroupRsp:
		if len(data) < 1 {
			// this has been observed to happen due to insufficient privileges
			// (e.g. user when operator is required), and when the BMC does not
			// support the command (e.g. SuperMicro)
			df.SetTruncated()
			return 0, fmt.Errorf("data too short for body code")
		}
		m.Body = BodyCode(data[0])
		return 1, nil
	case NetworkFunctionOEMReq, NetworkFunctionOEMRsp:
		if len(data) < 3 {
			df.SetTruncated()
			return 0, fmt.Errorf("data too short for OEM EN")
		}
		m.Enterprise = iana.Enterprise(
			uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)
		return 3, nil
	default:
		return 0, nil
	}
}

func (m *Message) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	header, err := b.PrependBytes(m.serializeLength())
	if err != nil {
		return err
	}

	header[0] = uint8(m.RemoteAddress)
	header[1] = uint8(m.Function)<<2 | uint8(m.RemoteLUN)

	if opts.ComputeChecksums {
		m.Checksum1 = checksum(header[0:2])
	}
	header[2] = m.Checksum1

	header[3] = uint8(m.LocalAddress)
	header[4] = uint8(m.Sequence)<<2 | uint8(m.LocalLUN)
	header[5] = uint8(m.Command)

	offset := 6

	if !m.Function.IsRequest() {
		// completion code
		header[offset] = uint8(m.CompletionCode)
		offset++
	}

	switch m.Function {
	case NetworkFunctionGroupReq, NetworkFunctionGroupRsp:
		// body code
		header[offset] = uint8(m.Body)
	case NetworkFunctionOEMReq, NetworkFunctionOEMRsp:
		// OEM enterprise number
		enterprise := uint32(m.Enterprise)
		header[offset] = uint8(enterprise)
		header[offset+1] = uint8(enterprise >> 8)
		header[offset+2] = uint8(enterprise >> 16)
	}

	if opts.ComputeChecksums {
		payload := b.Bytes()
		m.Checksum2 = checksum(payload[3:])
	}
	trailer, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	trailer[0] = m.Checksum2

	return nil
}

func (m *Message) serializeLength() int {
	length := 6
	if !m.Function.IsRequest() {
		// completion code
		length++
	}
	switch m.Function {
	case NetworkFunctionGroupReq, NetworkFunctionGroupRsp:
		// body code
		length++
	case NetworkFunctionOEMReq, NetworkFunctionOEMRsp:
		// OEM enterprise number
		length += 3
	}
	return length
}

// checksum calculates the 2's complement checksum of a slice of data. The
// algorithm is defined in section 13.8 of the IPMI v2.0 spec.
func checksum(data []byte) uint8 {
	c := uint8(0)
	for _, b := range data {
		c += uint8(b) // overflow is safe
	}
	return -c
}
