// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.4
// source: signature.proto

package grpcsig

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Nothing struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Nothing) Reset() {
	*x = Nothing{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Nothing) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Nothing) ProtoMessage() {}

func (x *Nothing) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Nothing.ProtoReflect.Descriptor instead.
func (*Nothing) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{0}
}

type SignatureMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ID          string                `protobuf:"bytes,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Version     string                `protobuf:"bytes,2,opt,name=Version,proto3" json:"Version,omitempty"`
	Name        string                `protobuf:"bytes,3,opt,name=Name,proto3" json:"Name,omitempty"`
	Description string                `protobuf:"bytes,4,opt,name=Description,proto3" json:"Description,omitempty"`
	Tags        []string              `protobuf:"bytes,5,rep,name=Tags,proto3" json:"Tags,omitempty"`
	Properties  map[string]*anypb.Any `protobuf:"bytes,6,rep,name=Properties,proto3" json:"Properties,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *SignatureMetadata) Reset() {
	*x = SignatureMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureMetadata) ProtoMessage() {}

func (x *SignatureMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureMetadata.ProtoReflect.Descriptor instead.
func (*SignatureMetadata) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{1}
}

func (x *SignatureMetadata) GetID() string {
	if x != nil {
		return x.ID
	}
	return ""
}

func (x *SignatureMetadata) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *SignatureMetadata) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SignatureMetadata) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *SignatureMetadata) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *SignatureMetadata) GetProperties() map[string]*anypb.Any {
	if x != nil {
		return x.Properties
	}
	return nil
}

type SignatureEventSelectors struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventSelectors []*SignatureEventSelectors_Selector `protobuf:"bytes,1,rep,name=EventSelectors,proto3" json:"EventSelectors,omitempty"`
}

func (x *SignatureEventSelectors) Reset() {
	*x = SignatureEventSelectors{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureEventSelectors) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureEventSelectors) ProtoMessage() {}

func (x *SignatureEventSelectors) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureEventSelectors.ProtoReflect.Descriptor instead.
func (*SignatureEventSelectors) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{2}
}

func (x *SignatureEventSelectors) GetEventSelectors() []*SignatureEventSelectors_Selector {
	if x != nil {
		return x.EventSelectors
	}
	return nil
}

type Headers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ContentType string `protobuf:"bytes,1,opt,name=ContentType,proto3" json:"ContentType,omitempty"`
	Origin      string `protobuf:"bytes,2,opt,name=Origin,proto3" json:"Origin,omitempty"`
}

func (x *Headers) Reset() {
	*x = Headers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Headers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Headers) ProtoMessage() {}

func (x *Headers) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Headers.ProtoReflect.Descriptor instead.
func (*Headers) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{3}
}

func (x *Headers) GetContentType() string {
	if x != nil {
		return x.ContentType
	}
	return ""
}

func (x *Headers) GetOrigin() string {
	if x != nil {
		return x.Origin
	}
	return ""
}

type Event struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Headers *Headers        `protobuf:"bytes,1,opt,name=Headers,proto3" json:"Headers,omitempty"`
	Payload *structpb.Value `protobuf:"bytes,2,opt,name=Payload,proto3" json:"Payload,omitempty"`
}

func (x *Event) Reset() {
	*x = Event{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Event) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Event) ProtoMessage() {}

func (x *Event) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Event.ProtoReflect.Descriptor instead.
func (*Event) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{4}
}

func (x *Event) GetHeaders() *Headers {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *Event) GetPayload() *structpb.Value {
	if x != nil {
		return x.Payload
	}
	return nil
}

type Finding struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data    map[string]*anypb.Any `protobuf:"bytes,1,rep,name=Data,proto3" json:"Data,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Context *Event                `protobuf:"bytes,2,opt,name=Context,proto3" json:"Context,omitempty"`
}

func (x *Finding) Reset() {
	*x = Finding{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Finding) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Finding) ProtoMessage() {}

func (x *Finding) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Finding.ProtoReflect.Descriptor instead.
func (*Finding) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{5}
}

func (x *Finding) GetData() map[string]*anypb.Any {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *Finding) GetContext() *Event {
	if x != nil {
		return x.Context
	}
	return nil
}

type SignatureEventSelectors_Selector struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source string `protobuf:"bytes,1,opt,name=Source,proto3" json:"Source,omitempty"`
	Name   string `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	Origin string `protobuf:"bytes,3,opt,name=Origin,proto3" json:"Origin,omitempty"`
}

func (x *SignatureEventSelectors_Selector) Reset() {
	*x = SignatureEventSelectors_Selector{}
	if protoimpl.UnsafeEnabled {
		mi := &file_signature_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureEventSelectors_Selector) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureEventSelectors_Selector) ProtoMessage() {}

func (x *SignatureEventSelectors_Selector) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureEventSelectors_Selector.ProtoReflect.Descriptor instead.
func (*SignatureEventSelectors_Selector) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{2, 0}
}

func (x *SignatureEventSelectors_Selector) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *SignatureEventSelectors_Selector) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SignatureEventSelectors_Selector) GetOrigin() string {
	if x != nil {
		return x.Origin
	}
	return ""
}

var File_signature_proto protoreflect.FileDescriptor

var file_signature_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74,
	0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x09, 0x0a, 0x07, 0x4e, 0x6f,
	0x74, 0x68, 0x69, 0x6e, 0x67, 0x22, 0xa0, 0x02, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x0e, 0x0a, 0x02, 0x49,
	0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x49, 0x44, 0x12, 0x18, 0x0a, 0x07, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x54,
	0x61, 0x67, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x54, 0x61, 0x67, 0x73, 0x12,
	0x42, 0x0a, 0x0a, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x18, 0x06, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69,
	0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74,
	0x69, 0x65, 0x73, 0x1a, 0x53, 0x0a, 0x0f, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xb4, 0x01, 0x0a, 0x17, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x6c, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x73, 0x12, 0x49, 0x0a, 0x0e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x2e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52,
	0x0e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x1a,
	0x4e, 0x0a, 0x08, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x53,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x4f, 0x72, 0x69, 0x67, 0x69,
	0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x22,
	0x43, 0x0a, 0x07, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06,
	0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x4f, 0x72,
	0x69, 0x67, 0x69, 0x6e, 0x22, 0x5d, 0x0a, 0x05, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x22, 0x0a,
	0x07, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08,
	0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x52, 0x07, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x73, 0x12, 0x30, 0x0a, 0x07, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x07, 0x50, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x22, 0xa2, 0x01, 0x0a, 0x07, 0x46, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x12,
	0x26, 0x0a, 0x04, 0x44, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x46, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x04, 0x44, 0x61, 0x74, 0x61, 0x12, 0x20, 0x0a, 0x07, 0x43, 0x6f, 0x6e, 0x74, 0x65,
	0x78, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x06, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x52, 0x07, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x1a, 0x4d, 0x0a, 0x09, 0x44, 0x61, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x32, 0x92, 0x01, 0x0a, 0x09, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x2b, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x08, 0x2e, 0x4e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x1a,
	0x12, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x37, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x12, 0x08, 0x2e, 0x4e, 0x6f, 0x74, 0x68, 0x69,
	0x6e, 0x67, 0x1a, 0x18, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x12, 0x1f, 0x0a, 0x07,
	0x4f, 0x6e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x06, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x1a,
	0x08, 0x2e, 0x46, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x28, 0x01, 0x30, 0x01, 0x42, 0x32, 0x5a,
	0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x71, 0x75, 0x61,
	0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2f,
	0x70, 0x6b, 0x67, 0x2f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x73, 0x69,
	0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_signature_proto_rawDescOnce sync.Once
	file_signature_proto_rawDescData = file_signature_proto_rawDesc
)

func file_signature_proto_rawDescGZIP() []byte {
	file_signature_proto_rawDescOnce.Do(func() {
		file_signature_proto_rawDescData = protoimpl.X.CompressGZIP(file_signature_proto_rawDescData)
	})
	return file_signature_proto_rawDescData
}

var file_signature_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_signature_proto_goTypes = []interface{}{
	(*Nothing)(nil),                          // 0: Nothing
	(*SignatureMetadata)(nil),                // 1: SignatureMetadata
	(*SignatureEventSelectors)(nil),          // 2: SignatureEventSelectors
	(*Headers)(nil),                          // 3: Headers
	(*Event)(nil),                            // 4: Event
	(*Finding)(nil),                          // 5: Finding
	nil,                                      // 6: SignatureMetadata.PropertiesEntry
	(*SignatureEventSelectors_Selector)(nil), // 7: SignatureEventSelectors.Selector
	nil,                                      // 8: Finding.DataEntry
	(*structpb.Value)(nil),                   // 9: google.protobuf.Value
	(*anypb.Any)(nil),                        // 10: google.protobuf.Any
}
var file_signature_proto_depIdxs = []int32{
	6,  // 0: SignatureMetadata.Properties:type_name -> SignatureMetadata.PropertiesEntry
	7,  // 1: SignatureEventSelectors.EventSelectors:type_name -> SignatureEventSelectors.Selector
	3,  // 2: Event.Headers:type_name -> Headers
	9,  // 3: Event.Payload:type_name -> google.protobuf.Value
	8,  // 4: Finding.Data:type_name -> Finding.DataEntry
	4,  // 5: Finding.Context:type_name -> Event
	10, // 6: SignatureMetadata.PropertiesEntry.value:type_name -> google.protobuf.Any
	10, // 7: Finding.DataEntry.value:type_name -> google.protobuf.Any
	0,  // 8: Signature.GetMetadata:input_type -> Nothing
	0,  // 9: Signature.GetEventSelectors:input_type -> Nothing
	4,  // 10: Signature.OnEvent:input_type -> Event
	1,  // 11: Signature.GetMetadata:output_type -> SignatureMetadata
	2,  // 12: Signature.GetEventSelectors:output_type -> SignatureEventSelectors
	5,  // 13: Signature.OnEvent:output_type -> Finding
	11, // [11:14] is the sub-list for method output_type
	8,  // [8:11] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_signature_proto_init() }
func file_signature_proto_init() {
	if File_signature_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_signature_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Nothing); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_signature_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureMetadata); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_signature_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureEventSelectors); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_signature_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Headers); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_signature_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Event); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_signature_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Finding); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_signature_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureEventSelectors_Selector); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_signature_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_signature_proto_goTypes,
		DependencyIndexes: file_signature_proto_depIdxs,
		MessageInfos:      file_signature_proto_msgTypes,
	}.Build()
	File_signature_proto = out.File
	file_signature_proto_rawDesc = nil
	file_signature_proto_goTypes = nil
	file_signature_proto_depIdxs = nil
}
