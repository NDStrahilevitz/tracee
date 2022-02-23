package grpcsig

import (
	"context"
	"io"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type GRPCSignature struct {
	URL            string
	metadata       detect.SignatureMetadata
	selectedEvents []detect.SignatureEventSelector
	cb             detect.SignatureHandler
	grpcConn       *grpc.ClientConn
	client         SignatureClient
	eventChan      chan protocol.Event
}

func convertAnyMapToIfaceMap(in map[string]*anypb.Any) map[string]interface{} {
	res := make(map[string]interface{}, len(in))

	for key, val := range in {
		res[key] = val
	}

	return res
}

func GrpcEventToProtocol(e *Event) protocol.Event {
	return protocol.Event{
		Headers: protocol.EventHeaders{
			ContentType: e.Headers.ContentType,
			Origin:      e.Headers.Origin,
		},
		Payload: e.Payload.AsInterface(),
	}
}

func (sig *GRPCSignature) scrapeMetadata() (detect.SignatureMetadata, error) {
	res, err := sig.client.GetMetadata(context.Background(), &Nothing{})

	if err != nil {
		return detect.SignatureMetadata{}, err
	}

	return detect.SignatureMetadata{
		ID:          res.ID,
		Version:     res.Version,
		Name:        res.Name,
		Description: res.Description,
		Tags:        res.Tags,
		Properties:  convertAnyMapToIfaceMap(res.Properties),
	}, nil
}
func (sig *GRPCSignature) scrapeSelectedEvents() ([]detect.SignatureEventSelector, error) {
	res, err := sig.client.GetEventSelectors(context.Background(), &Nothing{})

	if err != nil {
		return []detect.SignatureEventSelector{}, err
	}

	eventSelectors := make([]detect.SignatureEventSelector, len(res.GetEventSelectors()))

	for _, selector := range res.GetEventSelectors() {
		eventSelectors = append(eventSelectors, detect.SignatureEventSelector{
			Source: selector.Source,
			Name:   selector.Name,
			Origin: selector.Origin,
		})
	}

	return eventSelectors, nil
}

func (sig *GRPCSignature) GetMetadata() (detect.SignatureMetadata, error) {
	return sig.metadata, nil
}
func (sig *GRPCSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return sig.selectedEvents, nil
}
func (sig *GRPCSignature) Init(cb detect.SignatureHandler) error {
	conn, err := grpc.Dial(sig.URL, []grpc.DialOption{}...)
	if err != nil {
		return err
	}
	sig.grpcConn = conn
	sig.client = NewSignatureClient(sig.grpcConn)
	sig.cb = cb
	metadata, err := sig.scrapeMetadata()
	if err != nil {
		return err
	}
	selectedEvents, err := sig.scrapeSelectedEvents()
	if err != nil {
		return err
	}
	onEventClient, err := sig.client.OnEvent(context.TODO())
	if err != nil {
		return err
	}

	sig.selectedEvents = selectedEvents
	sig.metadata = metadata
	sig.eventChan = make(chan protocol.Event, 1000)

	go func() {
		for evt := range sig.eventChan {
			serializedPayload, err := structpb.NewValue(evt.Payload)
			if err != nil {
				continue
			}
			onEventClient.Send(&Event{
				Headers: &Headers{
					Origin:      evt.Headers.Origin,
					ContentType: evt.Headers.ContentType,
				},
				Payload: serializedPayload,
			})
		}
	}()

	go func() {
		for {
			in, err := onEventClient.Recv()
			if err == io.EOF {
				sig.Close()
				return
			}
			if err != nil {
				continue
			}
			cb(detect.Finding{
				Data:        convertAnyMapToIfaceMap(in.Data),
				Event:       GrpcEventToProtocol(in.Context),
				SigMetadata: sig.metadata,
			})
		}
	}()

	return nil
}

func (sig *GRPCSignature) Close() {
	sig.grpcConn.Close()
}

func (sig *GRPCSignature) OnEvent(event protocol.Event) error {
	sig.eventChan <- event
	return nil
}

func (sig *GRPCSignature) OnSignal(signal detect.Signal) error {
	return nil
}
