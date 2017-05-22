package saml

import (
	"encoding/xml"
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

type LocalizedName struct {
	Lang  string `xml:"xml lang,attr"`
	Value string `xml:",chardata"`
}

type LocalizedURI struct {
	Lang  string
	Value string
}

type OrganizationName LocalizedName

type OrganizationDisplayName LocalizedName

type OrganizationURL LocalizedURI

type ContactPerson struct {
	ContactType      string `xml:"contactType,attr"`
	Company          string
	GivenName        string
	SurName          string
	EmailAddresses   []string
	TelephoneNumbers []string
}

type AdditionalMetadataLocation string

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

// KeyDescriptor represents the XMLSEC object of the same name
type KeyDescriptor struct {
	Use               string             `xml:"use,attr"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

// EncryptionMethod represents the XMLSEC object of the same name
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo represents the XMLSEC object of the same name
//
// TODO(ross): revisit xmldsig and make this type more complete
type KeyInfo struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	Certificate string   `xml:"X509Data>X509Certificate"`
}

// Endpoint represents the SAML EndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf section 2.2.2
type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
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

type SSODescriptor struct {
	RoleDescriptor
	ArtifactResolutionServices []IndexedEndpoint `xml:"ArtifactResolutionService"`
	SingleLogoutServices       []Endpoint        `xml:"SingleLogoutService"`
	ManageNameIDServices       []Endpoint        `xml:"ManageNameIDService"`
	NameIDFormats              []NameIDFormat    `xml:"NameIDFormat"`
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

type SingleSignOnService Endpoint

type NameIDMappingService Endpoint

type AssertionIDRequestService Endpoint

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

type AttributeConsumingService struct {
	Index               int                  `xml:"index,attr"`
	IsDefault           *bool                `xml:"isDefault,attr"`
	ServiceNames        []ServiceName        `xml:"ServiceName"`
	ServiceDescriptions []ServiceDescription `xml:"ServiceDescription"`
	RequestedAttributes []RequestedAttribute `xml:"RequestedAttribute"`
}

type ServiceName LocalizedName

type ServiceDescription LocalizedName

type RequestedAttribute struct {
	Attribute
	IsRequired *bool `xml:"isRequired,attr"`
}

type AuthnAuthorityDescriptor struct {
	RoleDescriptor
	AuthnQueryServices         []AuthnQueryService         `xml:"AuthnQueryService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat              `xml:"NameIDFormat"`
}

type AuthnQueryService Endpoint

type PDPDescriptor struct {
	RoleDescriptor
	AuthzServices              []AuthzService              `xml:"AuthzService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat              `xml:"NameIDFormat"`
}

type AuthzService Endpoint

type AttributeAuthorityDescriptor struct {
	RoleDescriptor
	AttributeServices          []AttributeService          `xml:"AttributeService"`
	AssertionIDRequestServices []AssertionIDRequestService `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat              `xml:"NameIDFormat"`
	AttributeProfiles          []AttributeProfile          `xml:"AttributeProfile"`
	Attributes                 []Attribute                 `xml:"Attribute"`
}

type AttributeService Endpoint

type AffiliationDescriptor struct {
	AffiliationOwnerID string        `xml:"affiliationOwnerID,attr"`
	ID                 string        `xml:",attr"`
	ValidUntil         time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration      time.Duration `xml:"cacheDuration,attr"`
	Signature          *etree.Element
	AffiliateMembers   []AffiliateMember `xml:"AffiliateMember"`
	KeyDescriptors     []KeyDescriptor   `xml:"KeyDescriptor"`
}

// TODO(ross): find out where this is documented
type AffiliateMember struct {
}
