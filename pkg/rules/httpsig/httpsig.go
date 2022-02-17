package httpsig

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aquasecurity/tracee/types"
)

type HttpSignature struct {
	url            string
	metadata       types.SignatureMetadata
	selectedEvents []types.SignatureEventSelector
	cb             types.SignatureHandler
	client         http.Client
}

type httpResponse struct {
	response *http.Response
	err      error
}

func (sig *HttpSignature) scrapeMetadata() (types.SignatureMetadata, error) {
	respChan := make(chan httpResponse)
	var res types.SignatureMetadata

	go func() {
		resp, err := sig.client.Get(sig.url + "/metadata")

		if err != nil {
			respChan <- httpResponse{
				err: err,
			}
		}

		respChan <- httpResponse{
			response: resp,
		}
	}()
	resp := <-respChan

	if resp.err != nil {
		return res, resp.err
	}

	defer resp.response.Body.Close()

	err := json.NewDecoder(resp.response.Body).Decode(res)

	if err != nil {
		return res, err
	}

	return res, nil
}
func (sig *HttpSignature) scrapeSelectedEvents() ([]types.SignatureEventSelector, error) {
	respChan := make(chan httpResponse)
	var res []types.SignatureEventSelector

	go func() {
		resp, err := sig.client.Get(sig.url + "/events")

		if err != nil {
			respChan <- httpResponse{
				err: err,
			}
		}

		respChan <- httpResponse{
			response: resp,
		}
	}()
	resp := <-respChan

	if resp.err != nil {
		return res, resp.err
	}

	defer resp.response.Body.Close()

	err := json.NewDecoder(resp.response.Body).Decode(res)

	if err != nil {
		return res, err
	}

	return res, nil
}

func (sig *HttpSignature) GetMetadata() (types.SignatureMetadata, error) {
	return sig.metadata, nil
}
func (sig *HttpSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return sig.selectedEvents, nil
}
func (sig *HttpSignature) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	metadata, err := sig.scrapeMetadata()
	if err != nil {
		return err
	}
	selectedEvents, err := sig.scrapeSelectedEvents()
	if err != nil {
		return err
	}
	sig.selectedEvents = selectedEvents
	sig.metadata = metadata
	return nil
}
func (sig *HttpSignature) Close() {
	sig.client.CloseIdleConnections()
}
func (sig *HttpSignature) OnEvent(event types.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	return nil
}
func (sig *HttpSignature) OnSignal(signal types.Signal) error {
	return nil
}
