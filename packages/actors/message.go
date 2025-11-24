package actors

type MessageType = byte

type MessagePayload interface {
	MsgType() MessageType
}

type MessageIn struct {
	Sender  NodeID
	Payload MessagePayload
}

func NewMessageIn(sender NodeID, payload MessagePayload) MessageIn {
	return MessageIn{
		Sender:  sender,
		Payload: payload,
	}
}

type MessageOut struct {
	Recipient NodeID
	Payload   MessagePayload
}

func NewMessageOut(recipient NodeID, payload MessagePayload) MessageOut {
	return MessageOut{
		Recipient: recipient,
		Payload:   payload,
	}
}

type MessageOutWithPath struct {
	MessageOut
	Path Path
}
