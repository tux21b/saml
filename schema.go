package saml

import (
	"encoding/xml"
	"strconv"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// AuthnRequest represents the SAML object of the same name, a request from a service provider
// to authenticate a user.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	Subject      *Subject
	NameIDPolicy *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Conditions   *Conditions
	//RequestedAuthnContext *RequestedAuthnContext // TODO
	//Scoping               *Scoping // TODO

	ForceAuthn                     *bool  `xml:",attr"`
	IsPassive                      *bool  `xml:",attr"`
	AssertionConsumerServiceIndex  string `xml:",attr"`
	AssertionConsumerServiceURL    string `xml:",attr"`
	ProtocolBinding                string `xml:",attr"`
	AttributeConsumingServiceIndex string `xml:",attr"`
	ProviderName                   string `xml:",attr"`
}

func (r *AuthnRequest) Element() *etree.Element {
	el := etree.NewElement("samlp:AuthnRequest")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", r.IssueInstant.Format(timeFormat))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	if r.Subject != nil {
		el.AddChild(r.Subject.Element())
	}
	if r.NameIDPolicy != nil {
		el.AddChild(r.NameIDPolicy.Element())
	}
	if r.Conditions != nil {
		el.AddChild(r.Conditions.Element())
	}
	//if r.RequestedAuthnContext != nil {
	//	el.AddChild(r.RequestedAuthnContext.Element())
	//}
	//if r.Scoping != nil {
	//	el.AddChild(r.Scoping.Element())
	//}
	if r.ForceAuthn != nil {
		el.CreateAttr("ForceAuthn", strconv.FormatBool(*r.ForceAuthn))
	}
	if r.IsPassive != nil {
		el.CreateAttr("IsPassive", strconv.FormatBool(*r.IsPassive))
	}
	if r.AssertionConsumerServiceIndex != "" {
		el.CreateAttr("AssertionConsumerServiceIndex", r.AssertionConsumerServiceIndex)
	}
	if r.AssertionConsumerServiceURL != "" {
		el.CreateAttr("AssertionConsumerServiceURL", r.AssertionConsumerServiceURL)
	}
	if r.ProtocolBinding != "" {
		el.CreateAttr("ProtocolBinding", r.ProtocolBinding)
	}
	if r.AttributeConsumingServiceIndex != "" {
		el.CreateAttr("AttributeConsumingServiceIndex", r.AttributeConsumingServiceIndex)
	}
	if r.ProviderName != "" {
		el.CreateAttr("ProviderName", r.ProviderName)
	}
	return el
}

func (a *AuthnRequest) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		IssueInstant: RelaxedTime(a.IssueInstant),
		Alias:        (*Alias)(a),
	}
	return e.Encode(aux)
}

func (a *AuthnRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Issuer represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Issuer struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameQualifier   string   `xml:",attr"`
	SPNameQualifier string   `xml:",attr"`
	Format          string   `xml:",attr"`
	SPProvidedID    string   `xml:",attr"`
	Value           string   `xml:",chardata"`
}

func (a *Issuer) Element() *etree.Element {
	el := etree.NewElement("saml:Issuer")
	if a.NameQualifier != "" {
		el.CreateAttr("NameQualifier", a.NameQualifier)
	}
	if a.SPNameQualifier != "" {
		el.CreateAttr("SPNameQualifier", a.SPNameQualifier)
	}
	if a.Format != "" {
		el.CreateAttr("Format", a.Format)
	}
	if a.SPProvidedID != "" {
		el.CreateAttr("SPProvidedID", a.SPProvidedID)
	}
	el.SetText(a.Value)
	return el
}

// NameIDPolicy represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDPolicy struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format          *string  `xml:",attr"`
	SPNameQualifier *string  `xml:",attr"`
	AllowCreate     *bool    `xml:",attr"`
}

func (a *NameIDPolicy) Element() *etree.Element {
	el := etree.NewElement("samlp:NameIDPolicy")
	if a.Format != nil {
		el.CreateAttr("Format", *a.Format)
	}
	if a.SPNameQualifier != nil {
		el.CreateAttr("SPNameQualifier", *a.SPNameQualifier)
	}
	if a.AllowCreate != nil {
		el.CreateAttr("AllowCreate", strconv.FormatBool(*a.AllowCreate))
	}
	return el
}

// Response represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Response struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Status       Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// TODO(ross): more than one EncryptedAssertion is allowed
	EncryptedAssertion *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`

	// TODO(ross): more than one Assertion is allowed
	Assertion *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

func (r *Response) Element() *etree.Element {
	el := etree.NewElement("samlp:Response")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

	// Note: This namespace is not used by any element or attribute name, but
	// is required so that the AttributeValue type element can have a value like
	// "xs:string". If we don't declare it here, then it will be stripped by the
	// cannonicalizer. This could be avoided by providing a prefix list to the
	// cannonicalizer, but prefix lists do not appear to be implemented correctly
	// in some libraries, so the safest action is to always produce XML that is
	// (a) in cannonical form and (b) does not require prefix lists.
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")

	el.CreateAttr("ID", r.ID)
	if r.InResponseTo != "" {
		el.CreateAttr("InResponseTo", r.InResponseTo)
	}
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", r.IssueInstant.Format(timeFormat))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	el.AddChild(r.Status.Element())
	if r.EncryptedAssertion != nil {
		el.AddChild(r.EncryptedAssertion)
	}
	if r.Assertion != nil {
		el.AddChild(r.Assertion.Element())
	}
	return el
}

func (r *Response) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

func (r *Response) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Status represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Status struct {
	XMLName       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode    StatusCode
	StatusMessage *StatusMessage
	StatusDetail  *StatusDetail
}

func (s *Status) Element() *etree.Element {
	el := etree.NewElement("samlp:Status")
	el.AddChild(s.StatusCode.Element())
	if s.StatusMessage != nil {
		el.AddChild(s.StatusMessage.Element())
	}
	if s.StatusDetail != nil {
		el.AddChild(s.StatusDetail.Element())
	}
	return el
}

// StatusCode represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusCode struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value      string   `xml:",attr"`
	StatusCode *StatusCode
}

func (s *StatusCode) Element() *etree.Element {
	el := etree.NewElement("samlp:StatusCode")
	el.CreateAttr("Value", s.Value)
	if s.StatusCode != nil {
		el.AddChild(s.StatusCode.Element())
	}
	return el
}

// StatusSuccess means The request succeeded. Additional information MAY be returned in the <StatusMessage> and/or <StatusDetail> elements.
var StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

const (
	// The permissible top-level <StatusCode> values are as follows:

	// The request could not be performed due to an error on the part of the requester.
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"

	//The request could not be performed due to an error on the part of the SAML responder or SAML
	//authority.
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"

	//The SAML responder could not process the request because the version of the request message was
	//incorrect.
	StatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

	// The following second-level status codes are referenced at various places in this specification. Additional
	// second-level status codes MAY be defined in future versions of the SAML specification. System entities
	// are free to define more specific status codes by defining appropriate URI references.

	// The responding provider was unable to successfully authenticate the principal.
	StatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	// Unexpected or invalid content was encountered within a <saml:Attribute> or
	// <saml:AttributeValue> element.
	StatusInvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

	// The responding provider cannot or will not support the requested name identifier policy.
	StatusInvalidNameIDPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

	// The specified authentication context requirements cannot be met by the responder.
	StatusNoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

	// Used by an intermediary to indicate that none of the supported identity provider <Loc> elements in an
	// <IDPList> can be resolved or that none of the supported identity providers are available.
	StatusNoAvailableIDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

	// Indicates the responding provider cannot authenticate the principal passively, as has been requested.
	StatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"

	// Used by an intermediary to indicate that none of the identity providers in an <IDPList> are
	// supported by the intermediary.
	StatusNoSupportedIDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

	// Used by a session authority to indicate to a session participant that it was not able to propagate logout
	// to all other session participants.
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

	// Indicates that a responding provider cannot authenticate the principal directly and is not permitted to
	// proxy the request further.
	StatusProxyCountExceeded = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

	// The SAML responder or SAML authority is able to process the request but has chosen not to respond.
	// This status code MAY be used when there is concern about the security context of the request
	// message or the sequence of request messages received from a particular requester.
	StatusRequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

	// The SAML responder or SAML authority does not support the request.
	StatusRequestUnsupported = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

	// The SAML responder cannot process any requests with the protocol version specified in the request.
	StatusRequestVersionDeprecated = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"

	// The SAML responder cannot process the request because the protocol version specified in the
	// request message is a major upgrade from the highest protocol version supported by the responder.
	StatusRequestVersionTooHigh = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"

	// The SAML responder cannot process the request because the protocol version specified in the
	// request message is too low.
	StatusRequestVersionTooLow = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

	// The resource value provided in the request message is invalid or unrecognized.
	StatusResourceNotRecognized = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

	// The response message would contain more elements than the SAML responder is able to return.
	StatusTooManyResponses = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

	// An entity that has no knowledge of a particular attribute profile has been presented with an attribute
	// drawn from that profile.
	StatusUnknownAttrProfile = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

	// The responding provider does not recognize the principal specified or implied by the request.
	StatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

	// The SAML responder cannot properly fulfill the request using the protocol binding specified in the
	// request.
	StatusUnsupportedBinding = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

type StatusMessage struct {
	Value string
}

func (sm StatusMessage) Element() *etree.Element {
	el := etree.NewElement("samlp:StatusMessage")
	el.SetText(sm.Value)
	return el
}

type StatusDetail struct {
	Children []*etree.Element
}

func (sm StatusDetail) Element() *etree.Element {
	el := etree.NewElement("samlp:StatusDetail")
	for _, child := range sm.Children {
		el.AddChild(child)
	}
	return el
}

// Assertion represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Assertion struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID           string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Version      string    `xml:",attr"`
	Issuer       Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Subject      *Subject
	Conditions   *Conditions
	// Advice *Advice
	// Statements []Statement
	AuthnStatements []AuthnStatement `xml:"AuthnStatement"`
	// AuthzDecisionStatements []AuthzDecisionStatement
	AttributeStatements []AttributeStatement `xml:"AttributeStatement"`
}

func (a *Assertion) Element() *etree.Element {
	el := etree.NewElement("saml:Assertion")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("ID", a.ID)
	el.CreateAttr("IssueInstant", a.IssueInstant.Format(timeFormat))
	el.AddChild(a.Issuer.Element())
	if a.Signature != nil {
		el.AddChild(a.Signature)
	}
	if a.Subject != nil {
		el.AddChild(a.Subject.Element())
	}
	if a.Conditions != nil {
		el.AddChild(a.Conditions.Element())
	}
	for _, authnStatement := range a.AuthnStatements {
		el.AddChild(authnStatement.Element())
	}
	for _, attributeStatement := range a.AttributeStatements {
		el.AddChild(attributeStatement.Element())
	}
	err := etreeutils.TransformExcC14n(el, canonicalizerPrefixList)
	if err != nil {
		panic(err)
	}
	return el
}

func (a *Assertion) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Assertion
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Subject represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Subject struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	// BaseID               *BaseID  ... TODO
	NameID *NameID
	// EncryptedID          *EncryptedID  ... TODO
	SubjectConfirmations []SubjectConfirmation `xml:"SubjectConfirmation"`
}

func (a *Subject) Element() *etree.Element {
	el := etree.NewElement("saml:Subject")
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	for _, v := range a.SubjectConfirmations {
		el.AddChild(v.Element())
	}
	return el
}

// NameID represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameID struct {
	NameQualifier   string `xml:",attr"`
	SPNameQualifier string `xml:",attr"`
	Format          string `xml:",attr"`
	SPProvidedID    string `xml:",attr"`
	Value           string `xml:",chardata"`
}

func (a *NameID) Element() *etree.Element {
	el := etree.NewElement("saml:NameID")
	if a.NameQualifier != "" {
		el.CreateAttr("NameQualifier", a.NameQualifier)
	}
	if a.SPNameQualifier != "" {
		el.CreateAttr("SPNameQualifier", a.SPNameQualifier)
	}
	if a.Format != "" {
		el.CreateAttr("Format", a.Format)
	}
	if a.SPProvidedID != "" {
		el.CreateAttr("SPProvidedID", a.SPProvidedID)
	}
	if a.Value != "" {
		el.SetText(a.Value)
	}
	return el
}

// SubjectConfirmation represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmation struct {
	Method string `xml:",attr"`
	// BaseID               *BaseID  ... TODO
	NameID *NameID
	// EncryptedID          *EncryptedID  ... TODO
	SubjectConfirmationData *SubjectConfirmationData
}

func (a *SubjectConfirmation) Element() *etree.Element {
	el := etree.NewElement("saml:SubjectConfirmation")
	el.CreateAttr("Method", a.Method)
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	if a.SubjectConfirmationData != nil {
		el.AddChild(a.SubjectConfirmationData.Element())
	}
	return el
}

// SubjectConfirmationData represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmationData struct {
	NotBefore    time.Time `xml:",attr"`
	NotOnOrAfter time.Time `xml:",attr"`
	Recipient    string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Address      string    `xml:",attr"`
}

func (a *SubjectConfirmationData) Element() *etree.Element {
	el := etree.NewElement("saml:SubjectConfirmationData")
	if !a.NotBefore.IsZero() {
		el.CreateAttr("NotBefore", a.NotBefore.Format(timeFormat))
	}
	if !a.NotOnOrAfter.IsZero() {
		el.CreateAttr("NotOnOrAfter", a.NotOnOrAfter.Format(timeFormat))
	}
	if a.Recipient != "" {
		el.CreateAttr("Recipient", a.Recipient)
	}
	if a.InResponseTo != "" {
		el.CreateAttr("InResponseTo", a.InResponseTo)
	}
	if a.Address != "" {
		el.CreateAttr("Address", a.Address)
	}
	return el
}

func (s *SubjectConfirmationData) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		NotOnOrAfter: RelaxedTime(s.NotOnOrAfter),
		Alias:        (*Alias)(s),
	}
	return e.EncodeElement(aux, start)
}

func (s *SubjectConfirmationData) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	s.NotOnOrAfter = time.Time(aux.NotOnOrAfter)
	return nil
}

// Conditions represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Conditions struct {
	NotBefore            time.Time             `xml:",attr"`
	NotOnOrAfter         time.Time             `xml:",attr"`
	Conditions           []Condition           `xml:"Condition"` // extension point
	AudienceRestrictions []AudienceRestriction `xml:"AudienceRestriction"`
	OneTimeUse           *OneTimeUse
	ProxyRestriction     *ProxyRestriction
}

func (a *Conditions) Element() *etree.Element {
	el := etree.NewElement("saml:Conditions")
	if !a.NotBefore.IsZero() {
		el.CreateAttr("NotBefore", a.NotBefore.Format(timeFormat))
	}
	if !a.NotOnOrAfter.IsZero() {
		el.CreateAttr("NotOnOrAfter", a.NotOnOrAfter.Format(timeFormat))
	}
	for _, v := range a.Conditions {
		el.AddChild(v.Element())
	}
	for _, v := range a.AudienceRestrictions {
		el.AddChild(v.Element())
	}
	if a.OneTimeUse != nil {
		el.AddChild(a.OneTimeUse.Element())
	}
	if a.ProxyRestriction != nil {
		el.AddChild(a.ProxyRestriction.Element())
	}
	return el
}

func (c *Conditions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Conditions
	aux := &struct {
		NotBefore    RelaxedTime `xml:",attr"`
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		NotBefore:    RelaxedTime(c.NotBefore),
		NotOnOrAfter: RelaxedTime(c.NotOnOrAfter),
		Alias:        (*Alias)(c),
	}
	return e.EncodeElement(aux, start)
}

func (c *Conditions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Conditions
	aux := &struct {
		NotBefore    RelaxedTime `xml:",attr"`
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	c.NotBefore = time.Time(aux.NotBefore)
	c.NotOnOrAfter = time.Time(aux.NotOnOrAfter)
	return nil
}

type Condition etree.Element

func (a *Condition) Element() *etree.Element {
	return (*etree.Element)(a)
}

// AudienceRestriction represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AudienceRestriction struct {
	Audience Audience
}

func (a *AudienceRestriction) Element() *etree.Element {
	el := etree.NewElement("saml:AudienceRestriction")
	el.AddChild(a.Audience.Element())
	return el
}

// Audience represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Audience struct {
	Value string `xml:",chardata"`
}

func (a *Audience) Element() *etree.Element {
	el := etree.NewElement("saml:Audience")
	el.SetText(a.Value)
	return el
}

type OneTimeUse struct{}

func (a *OneTimeUse) Element() *etree.Element {
	return etree.NewElement("saml:OneTimeUse")
}

type ProxyRestriction struct {
	Count     *int
	Audiences []Audience
}

func (a *ProxyRestriction) Element() *etree.Element {
	el := etree.NewElement("saml:ProxyRestriction")
	if a.Count != nil {
		el.CreateAttr("Count", strconv.Itoa(*a.Count))
	}
	for _, v := range a.Audiences {
		el.AddChild(v.Element())
	}
	return el
}

// AuthnStatement represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnStatement struct {
	AuthnInstant        time.Time  `xml:",attr"`
	SessionIndex        string     `xml:",attr"`
	SessionNotOnOrAfter *time.Time `xml:",attr"`
	SubjectLocality     *SubjectLocality
	AuthnContext        AuthnContext
}

func (a *AuthnStatement) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnStatement")
	el.CreateAttr("AuthnInstant", a.AuthnInstant.Format(timeFormat))
	if a.SessionIndex != "" {
		el.CreateAttr("SessionIndex", a.SessionIndex)
	}
	if a.SubjectLocality != nil {
		el.AddChild(a.SubjectLocality.Element())
	}
	el.AddChild(a.AuthnContext.Element())
	return el
}

func (a *AuthnStatement) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AuthnStatement
	aux := &struct {
		AuthnInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		AuthnInstant: RelaxedTime(a.AuthnInstant),
		Alias:        (*Alias)(a),
	}
	return e.EncodeElement(aux, start)
}

func (a *AuthnStatement) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnStatement
	aux := &struct {
		AuthnInstant RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.AuthnInstant = time.Time(aux.AuthnInstant)
	return nil
}

// SubjectLocality represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectLocality struct {
	Address string `xml:",attr"`
	DNSName string `xml:",attr"`
}

func (a *SubjectLocality) Element() *etree.Element {
	el := etree.NewElement("saml:SubjectLocality")
	if a.Address != "" {
		el.CreateAttr("Address", a.Address)
	}
	if a.DNSName != "" {
		el.CreateAttr("DNSName", a.DNSName)
	}
	return el
}

// AuthnContext represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnContext struct {
	AuthnContextClassRef *AuthnContextClassRef
	//AuthnContextDecl          *AuthnContextDecl        ... TODO
	//AuthnContextDeclRef       *AuthnContextDeclRef     ... TODO
	//AuthenticatingAuthorities []AuthenticatingAuthority... TODO
}

func (a *AuthnContext) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnContext")
	if a.AuthnContextClassRef != nil {
		el.AddChild(a.AuthnContextClassRef.Element())
	}
	return el
}

// AuthnContextClassRef represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnContextClassRef struct {
	Value string `xml:",chardata"`
}

func (a *AuthnContextClassRef) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnContextClassRef")
	el.SetText(a.Value)
	return el
}

// AttributeStatement represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

func (a *AttributeStatement) Element() *etree.Element {
	el := etree.NewElement("saml:AttributeStatement")
	for _, v := range a.Attributes {
		el.AddChild(v.Element())
	}
	return el
}

// Attribute represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Attribute struct {
	FriendlyName string           `xml:",attr"`
	Name         string           `xml:",attr"`
	NameFormat   string           `xml:",attr"`
	Values       []AttributeValue `xml:"AttributeValue"`
}

func (a *Attribute) Element() *etree.Element {
	el := etree.NewElement("saml:Attribute")
	if a.FriendlyName != "" {
		el.CreateAttr("FriendlyName", a.FriendlyName)
	}
	if a.Name != "" {
		el.CreateAttr("Name", a.Name)
	}
	if a.NameFormat != "" {
		el.CreateAttr("NameFormat", a.NameFormat)
	}
	for _, v := range a.Values {
		el.AddChild(v.Element())
	}
	return el
}

// AttributeValue represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeValue struct {
	Type   string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value  string `xml:",chardata"`
	NameID *NameID
}

func (a *AttributeValue) Element() *etree.Element {
	el := etree.NewElement("saml:AttributeValue")
	el.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	el.CreateAttr("xsi:type", a.Type)
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	el.SetText(a.Value)
	return el
}
