package saml

import (
	"encoding/xml"
	"strconv"
	"time"

	"github.com/beevik/etree"
)

// HTTPPostBinding is the official URN for the HTTP-POST binding (transport)
var HTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// HTTPRedirectBinding is the official URN for the HTTP-Redirect binding (transport)
var HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

// EntitiesDescriptor represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.3.1
type EntitiesDescriptor struct {
	XMLName             xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	ID                  *string        `xml:",attr,omitempty"`
	ValidUntil          *time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration       *time.Duration `xml:"cacheDuration,attr,omitempty"`
	Name                *string        `xml:",attr,omitempty"`
	Signature           *etree.Element
	EntitiesDescriptors []EntitiesDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	EntityDescriptors   []EntityDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
}

func (e EntitiesDescriptor) Element() *etree.Element {
	el := etree.NewElement("md:EntitiesDescriptor")
	el.CreateAttr("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata")
	if e.ID != nil {
		el.CreateAttr("ID", *e.ID)
	}
	if e.ValidUntil != nil {
		el.CreateAttr("validUntil", e.ValidUntil.Format(timeFormat))
	}
	if e.CacheDuration != nil {
		el.CreateAttr("cacheDuration", FormatDuration(*e.CacheDuration))
	}
	if e.Name != nil {
		el.CreateAttr("Name", *e.Name)
	}
	if e.Signature != nil {
		el.AddChild(e.Signature)
	}
	for _, entitiesDescriptor := range e.EntitiesDescriptors {
		el.AddChild(entitiesDescriptor.Element())
	}
	for _, entityDescriptor := range e.EntityDescriptors {
		el.AddChild(entityDescriptor.Element())
	}
	return el
}

// EntityDescriptor represents the SAML EntityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.3.2
type EntityDescriptor struct {
	XMLName       xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID      string        `xml:"entityID,attr"`
	ID            string        `xml:",attr,omitempty"`
	ValidUntil    time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration time.Duration `xml:"cacheDuration,attr,omitempty"`
	Signature     *etree.Element

	RoleDescriptors               []RoleDescriptor               `xml:"RoleDescriptor"`
	IDPSSODescriptors             []IDPSSODescriptor             `xml:"IDPSSODescriptor"`
	SPSSODescriptors              []SPSSODescriptor              `xml:"SPSSODescriptor"`
	AuthnAuthorityDescriptors     []AuthnAuthorityDescriptor     `xml:"AuthnAuthorityDescriptor"`
	AttributeAuthorityDescriptors []AttributeAuthorityDescriptor `xml:"AttributeAuthorityDescriptor"`
	PDPDescriptors                []PDPDescriptor                `xml:"PDPDescriptor"`

	AffiliationDescriptor       *AffiliationDescriptor
	Organization                *Organization
	ContactPerson               *ContactPerson
	AdditionalMetadataLocations []AdditionalMetadataLocation
}

func (e *EntityDescriptor) Element() *etree.Element {
	el := etree.NewElement("md:EntityDescriptor")
	el.CreateAttr("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata")
	el.CreateAttr("entityID", e.EntityID)
	if e.ID != "" {
		el.CreateAttr("ID", e.ID)
	}
	if !e.ValidUntil.IsZero() {
		el.CreateAttr("validUntil", e.ValidUntil.Format(timeFormat))
	}
	if e.CacheDuration != 0 {
		el.CreateAttr("cacheDuration", FormatDuration(e.CacheDuration))
	}
	if e.Signature != nil {
		el.AddChild(e.Signature)
	}
	for _, v := range e.RoleDescriptors {
		el.AddChild(v.Element())
	}
	for _, v := range e.IDPSSODescriptors {
		el.AddChild(v.Element())
	}
	for _, v := range e.SPSSODescriptors {
		el.AddChild(v.Element())
	}
	for _, v := range e.AuthnAuthorityDescriptors {
		el.AddChild(v.Element())
	}
	for _, v := range e.AttributeAuthorityDescriptors {
		el.AddChild(v.Element())
	}
	for _, v := range e.PDPDescriptors {
		el.AddChild(v.Element())
	}
	if e.AffiliationDescriptor != nil {
		el.AddChild(e.AffiliationDescriptor.Element())
	}
	if e.Organization != nil {
		el.AddChild(e.Organization.Element())
	}
	if e.ContactPerson != nil {
		el.AddChild(e.ContactPerson.Element())
	}
	for _, v := range e.AdditionalMetadataLocations {
		el.AddChild(v.Element())
	}
	return el
}

func (a *EntityDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias EntityDescriptor
	aux := &struct {
		ValidUntil RelaxedTime `xml:"validUntil,attr,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.ValidUntil = time.Time(aux.ValidUntil)
	return nil
}

type Organization struct {
	OrganizationNames        []OrganizationName        `xml:"OrganizationName"`
	OrganizationDisplayNames []OrganizationDisplayName `xml:"OrganizationDisplayName"`
	OrganizationURLs         []OrganizationURL         `xml:"OrganizationURL"`
}

func (e Organization) Element() *etree.Element {
	el := etree.NewElement("md:Organization")
	for _, v := range e.OrganizationNames {
		el.AddChild(v.Element())
	}
	for _, v := range e.OrganizationDisplayNames {
		el.AddChild(v.Element())
	}
	for _, v := range e.OrganizationURLs {
		el.AddChild(v.Element())
	}
	return el
}

type LocalizedName struct {
	Lang  string
	Value string
}

func (e LocalizedName) Element() *etree.Element {
	el := etree.NewElement("")
	el.CreateAttr("xml:lang", e.Lang)
	el.SetText(e.Value)
	return el
}

type LocalizedURI struct {
	Lang  string
	Value string
}

func (e LocalizedURI) Element() *etree.Element {
	el := etree.NewElement("")
	el.CreateAttr("xml:lang", e.Lang)
	el.SetText(e.Value)
	return el
}

type OrganizationName LocalizedName

func (e OrganizationName) Element() *etree.Element {
	el := LocalizedName(e).Element()
	el.Tag = "md:OrganizationName"
	return el
}

type OrganizationDisplayName LocalizedName

func (e OrganizationDisplayName) Element() *etree.Element {
	el := LocalizedName(e).Element()
	el.Tag = "md:OrganizationDisplayName"
	return el
}

type OrganizationURL LocalizedURI

func (e OrganizationURL) Element() *etree.Element {
	el := LocalizedName(e).Element()
	el.Tag = "md:OrganizationURL"
	return el
}

type ContactPerson struct {
	ContactType      string `xml:"contactType,attr"`
	Company          string
	GivenName        string
	SurName          string
	EmailAddresses   []string
	TelephoneNumbers []string
}

func (e ContactPerson) Element() *etree.Element {
	el := etree.NewElement("md:ContactPerson")
	el.CreateAttr("contactType", e.ContactType)
	if e.Company != "" {
		childEl := etree.NewElement("md:Company")
		childEl.SetText(e.Company)
		el.AddChild(childEl)
	}
	if e.GivenName != "" {
		childEl := etree.NewElement("md:GivenName")
		childEl.SetText(e.GivenName)
		el.AddChild(childEl)
	}
	if e.SurName != "" {
		childEl := etree.NewElement("md:SurName")
		childEl.SetText(e.SurName)
		el.AddChild(childEl)
	}
	for _, emailAddress := range e.EmailAddresses {
		childEl := etree.NewElement("md:EmailAddress")
		childEl.SetText(emailAddress)
		el.AddChild(childEl)
	}
	for _, telephoneNumber := range e.TelephoneNumbers {
		childEl := etree.NewElement("md:TelephoneNumber")
		childEl.SetText(telephoneNumber)
		el.AddChild(childEl)
	}
	return el
}

type AdditionalMetadataLocation string

func (e AdditionalMetadataLocation) Element() *etree.Element {
	el := etree.NewElement("md:AdditionalMetadataLocation")
	el.SetText(string(e))
	return el
}

type RoleDescriptor struct {
	ID                         string        `xml:",attr,omitempty"`
	ValidUntil                 time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration              time.Duration `xml:"cacheDuration,attr,omitempty"`
	ProtocolSupportEnumeration string        `xml:"protocolSupportEnumeration,attr"`
	ErrorURL                   string        `xml:"errorURL,attr,omitempty"`
	Signature                  *etree.Element
	KeyDescriptors             []KeyDescriptor `xml:"KeyDescriptor,omitempty"`
	Organization               *Organization   `xml:"Organization,omitempty"`
	ContactPeople              []ContactPerson `xml:"ContactPerson,omitempty"`
}

func (e RoleDescriptor) Element() *etree.Element {
	el := etree.NewElement("md:RoleDescriptor")
	if e.ID != "" {
		el.CreateAttr("ID", e.ID)
	}
	if !e.ValidUntil.IsZero() {
		el.CreateAttr("validUntil", e.ValidUntil.Format(timeFormat))
	}
	if e.CacheDuration != 0 {
		el.CreateAttr("cacheDuration", FormatDuration(e.CacheDuration))
	}
	el.CreateAttr("protocolSupportEnumeration", e.ProtocolSupportEnumeration)
	if e.ErrorURL != "" {
		el.CreateAttr("errorURL", e.ErrorURL)
	}
	if e.Signature != nil {
		el.AddChild(e.Signature)
	}
	for _, v := range e.KeyDescriptors {
		el.AddChild(v.Element())
	}
	if e.Organization != nil {
		el.AddChild(e.Organization.Element())
	}
	for _, v := range e.ContactPeople {
		el.AddChild(v.Element())
	}

	return el
}

// KeyDescriptor represents the XMLSEC object of the same name
type KeyDescriptor struct {
	Use               string             `xml:"use,attr"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

func (kd KeyDescriptor) Element() *etree.Element {
	el := etree.NewElement("md:KeyDescriptor")
	if kd.Use != "" {
		el.CreateAttr("use", kd.Use)
	}
	el.AddChild(kd.KeyInfo.Element())
	for _, v := range kd.EncryptionMethods {
		el.AddChild(v.Element())
	}
	return el
}

// EncryptionMethod represents the XMLSEC object of the same name
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

func (em EncryptionMethod) Element() *etree.Element {
	el := etree.NewElement("ds:EncryptionMethod")
	el.CreateAttr("Algorithm", em.Algorithm)
	return el
}

// KeyInfo represents the XMLSEC object of the same name
//
// TODO(ross): revisit xmldsig and make this type more complete
type KeyInfo struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	Certificate string   `xml:"X509Data>X509Certificate"`
}

func (ki KeyInfo) Element() *etree.Element {
	el := etree.NewElement("ds:KeyInfo")
	el.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	el2 := etree.NewElement("ds:X509Data")
	el.AddChild(el2)
	el3 := etree.NewElement("ds:X509Certificate")
	el3.SetText(ki.Certificate)
	el2.AddChild(el3)
	return el
}

// Endpoint represents the SAML EndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.2.2
type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

func (e Endpoint) Element() *etree.Element {
	el := etree.NewElement("md:EndpointType")
	el.CreateAttr("Binding", e.Binding)
	el.CreateAttr("Location", e.Location)
	if e.ResponseLocation != "" {
		el.CreateAttr("ResponseLocation", e.ResponseLocation)
	}
	return el
}

// IndexedEndpoint represents the SAML IndexedEndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.2.3
type IndexedEndpoint struct {
	Binding          string  `xml:"Binding,attr"`
	Location         string  `xml:"Location,attr"`
	ResponseLocation *string `xml:"ResponseLocation,attr,omitempty"`
	Index            int     `xml:"index,attr"`
	IsDefault        *bool   `xml:"isDefault,attr"`
}

func (e IndexedEndpoint) Element() *etree.Element {
	el := etree.NewElement("md:EndpointType")
	el.CreateAttr("Binding", e.Binding)
	el.CreateAttr("Location", e.Location)
	if e.ResponseLocation != nil {
		el.CreateAttr("ResponseLocation", *e.ResponseLocation)
	}
	el.CreateAttr("index", strconv.Itoa(e.Index))
	if e.IsDefault != nil {
		el.CreateAttr("isDefault", strconv.FormatBool(*e.IsDefault))
	}
	return el
}

type SSODescriptor struct {
	RoleDescriptor
	ArtifactResolutionServices []IndexedEndpoint `xml:"ArtifactResolutionService"`
	SingleLogoutServices       []Endpoint        `xml:"SingleLogoutService"`
	ManageNameIDServices       []Endpoint        `xml:"ManageNameIDService"`
	NameIDFormats              []NameIDFormat    `xml:"NameIDFormat"`
}

func (e SSODescriptor) Element() *etree.Element {
	el := e.RoleDescriptor.Element()
	el.Tag = "md:SSODescriptor"

	for _, v := range e.ArtifactResolutionServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.SingleLogoutServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.ManageNameIDServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.NameIDFormats {
		el.AddChild(v.Element())
	}
	return el
}

// IDPSSODescriptor represents the SAML IDPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.4.3
type IDPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	SSODescriptor
	WantAuthnRequestsSigned *bool `xml:",attr"`

	SingleSignOnServices       []SingleSignOnService       `xml:"SingleSignOnService"`
	NameIDMappingServices      []NameIDMappingService      `xml:"NameIDMappingService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	AttributeProfiles          []AttributeProfile          `xml:"AttributeProfile"`
	Attributes                 []Attribute                 `xml:"Attribute"`
}

func (e IDPSSODescriptor) Element() *etree.Element {
	el := e.SSODescriptor.Element()
	el.Tag = "md:IDPSSODescriptor"
	if e.WantAuthnRequestsSigned != nil {
		el.CreateAttr("WantAuthnRequestsSigned", strconv.FormatBool(*e.WantAuthnRequestsSigned))
	}

	for _, v := range e.SingleSignOnServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.NameIDMappingServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.AssertionIDRequestServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.AttributeProfiles {
		el.AddChild(v.Element())
	}
	for _, v := range e.Attributes {
		el.AddChild(v.Element())
	}
	return el
}

type SingleSignOnService Endpoint

func (ep SingleSignOnService) Element() *etree.Element {
	el := Endpoint(ep).Element()
	el.Tag = "md:SingleSignOnService"
	return el
}

type NameIDMappingService Endpoint

func (ep NameIDMappingService) Element() *etree.Element {
	el := Endpoint(ep).Element()
	el.Tag = "md:NameIDMappingService"
	return el
}

type AssertionIDRequestService Endpoint

func (ep AssertionIDRequestService) Element() *etree.Element {
	el := Endpoint(ep).Element()
	el.Tag = "md:AssertionIDRequestService"
	return el
}

type AttributeProfile string

func (ap AttributeProfile) Element() *etree.Element {
	el := etree.NewElement("md:AttributeProfile")
	el.SetText(string(ap))
	return el
}

// SPSSODescriptor represents the SAML SPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.4.2
type SPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	SSODescriptor
	AuthnRequestsSigned        *bool                       `xml:",attr"`
	WantAssertionsSigned       *bool                       `xml:",attr"`
	AssertionConsumerServices  []IndexedEndpoint           `xml:"AssertionConsumerService"`
	AttributeConsumingServices []AttributeConsumingService `xml:"AttributeConsumingService"`
}

func (e SPSSODescriptor) Element() *etree.Element {
	el := e.SSODescriptor.Element()
	el.Tag = "md:SPSSODescriptor"
	if e.AuthnRequestsSigned != nil {
		el.CreateAttr("AuthnRequestsSigned", strconv.FormatBool(*e.AuthnRequestsSigned))
	}
	if e.WantAssertionsSigned != nil {
		el.CreateAttr("WantAssertionsSigned", strconv.FormatBool(*e.WantAssertionsSigned))
	}
	for _, v := range e.AssertionConsumerServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.AttributeConsumingServices {
		el.AddChild(v.Element())
	}
	return el
}

type AttributeConsumingService struct {
	Index               int                  `xml:"index,attr"`
	IsDefault           *bool                `xml:"isDefault,attr"`
	ServiceNames        []ServiceName        `xml:"ServiceName"`
	ServiceDescriptions []ServiceDescription `xml:"ServiceDescription"`
	RequestedAttributes []RequestedAttribute `xml:"RequestedAttribute"`
}

func (e AttributeConsumingService) Element() *etree.Element {
	el := etree.NewElement("md:AttributeConsumingService")
	el.CreateAttr("index", strconv.Itoa(e.Index))
	if e.IsDefault != nil {
		el.CreateAttr("isDefault", strconv.FormatBool(*e.IsDefault))
	}
	for _, v := range e.ServiceNames {
		el.AddChild(v.Element())
	}
	for _, v := range e.ServiceDescriptions {
		el.AddChild(v.Element())
	}
	for _, v := range e.RequestedAttributes {
		el.AddChild(v.Element())
	}
	return el
}

type ServiceName LocalizedName

func (ap ServiceName) Element() *etree.Element {
	el := LocalizedName(ap).Element()
	el.Tag = "md:ServiceName"
	return el
}

type ServiceDescription LocalizedName

func (ap ServiceDescription) Element() *etree.Element {
	el := LocalizedName(ap).Element()
	el.Tag = "md:ServiceDescription"
	return el
}

type RequestedAttribute struct {
	Attribute
	IsRequired *bool `xml:"isRequired,attr"`
}

func (e RequestedAttribute) Element() *etree.Element {
	el := e.Attribute.Element()
	el.Tag = "md:RequestedAttribute"
	if e.IsRequired != nil {
		el.CreateAttr("isRequired", strconv.FormatBool(*e.IsRequired))
	}
	return el
}

type AuthnAuthorityDescriptor struct {
	RoleDescriptor
	AuthnQueryServices         []AuthnQueryService         `xml:"AuthnQueryService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat              `xml:"NameIDFormat"`
}

func (e AuthnAuthorityDescriptor) Element() *etree.Element {
	el := e.RoleDescriptor.Element()
	el.Tag = "md:AuthnAuthorityDescriptor"
	for _, v := range e.AuthnQueryServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.AssertionIDRequestServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.NameIDFormats {
		el.AddChild(v.Element())
	}
	return el
}

type AuthnQueryService Endpoint

func (a AuthnQueryService) Element() *etree.Element {
	el := Endpoint(a).Element()
	el.Tag = "md:AuthnQueryService"
	return el
}

type PDPDescriptor struct {
	RoleDescriptor
	AuthzServices              []AuthzService              `xml:"AuthzService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat              `xml:"NameIDFormat"`
}

func (e PDPDescriptor) Element() *etree.Element {
	el := e.RoleDescriptor.Element()
	el.Tag = "md:AuthnAuthorityDescriptor"
	for _, v := range e.AuthzServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.AssertionIDRequestServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.NameIDFormats {
		el.AddChild(v.Element())
	}
	return el
}

type AuthzService Endpoint

func (a AuthzService) Element() *etree.Element {
	el := Endpoint(a).Element()
	el.Tag = "md:AuthzService"
	return el
}

type AttributeAuthorityDescriptor struct {
	RoleDescriptor
	AttributeServices          []AttributeService          `xml:"AttributeService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat              `xml:"NameIDFormat"`
	AttributeProfiles          []AttributeProfile          `xml:"AttributeProfile"`
	Attributes                 []Attribute                 `xml:"Attribute"`
}

func (e AttributeAuthorityDescriptor) Element() *etree.Element {
	el := e.RoleDescriptor.Element()
	el.Tag = "md:AttributeAuthorityDescriptor"
	for _, v := range e.AttributeServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.AssertionIDRequestServices {
		el.AddChild(v.Element())
	}
	for _, v := range e.NameIDFormats {
		el.AddChild(v.Element())
	}
	for _, v := range e.AttributeProfiles {
		el.AddChild(v.Element())
	}
	for _, v := range e.Attributes {
		el.AddChild(v.Element())
	}
	return el
}

type AttributeService Endpoint

func (a AttributeService) Element() *etree.Element {
	el := Endpoint(a).Element()
	el.Tag = "md:AttributeService"
	return el
}

type AffiliationDescriptor struct {
	AffiliationOwnerID string        `xml:"affiliationOwnerID,attr"`
	ID                 string        `xml:",attr"`
	ValidUntil         time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration      time.Duration `xml:"cacheDuration,attr"`
	Signature          *etree.Element
	AffiliateMembers   []AffiliateMember `xml:"AffiliateMember"`
	KeyDescriptors     []KeyDescriptor   `xml:"KeyDescriptor"`
}

func (e AffiliationDescriptor) Element() *etree.Element {
	el := etree.NewElement("md:AffiliationDescriptor")
	el.CreateAttr("affiliationOwnerID", e.AffiliationOwnerID)
	if e.ID != "" {
		el.CreateAttr("ID", e.ID)
	}
	if !e.ValidUntil.IsZero() {
		el.CreateAttr("validUntil", e.ValidUntil.Format(timeFormat))
	}
	if e.CacheDuration != 0 {
		el.CreateAttr("cacheDuration", FormatDuration(e.CacheDuration))
	}
	if e.Signature != nil {
		el.AddChild(e.Signature)
	}
	for _, v := range e.AffiliateMembers {
		el.AddChild(v.Element())
	}
	for _, v := range e.KeyDescriptors {
		el.AddChild(v.Element())
	}
	return el
}

// TODO(ross): find out where this is documented
type AffiliateMember struct {
}

func (a AffiliateMember) Element() *etree.Element {
	panic("not implemented")
}
