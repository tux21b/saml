package saml

import (
	"encoding/xml"

	. "gopkg.in/check.v1"
)

var _ = Suite(&SchemaTest{})

type SchemaTest struct {
}

func (test *SchemaTest) TestAttributeXMLRoundTrip(c *C) {
	expected := Attribute{
		FriendlyName: "TestFriendlyName",
		Name:         "TestName",
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values: []AttributeValue{AttributeValue{
			Type:  "xs:string",
			Value: "test",
		}},
	}

	x, err := xml.Marshal(expected)
	c.Assert(err, IsNil)
	c.Assert(string(x), Equals, "<Attribute FriendlyName=\"TestFriendlyName\" "+
		"Name=\"TestName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">"+
		"<AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" "+
		"xsi:type=\"xs:string\">test</AttributeValue></Attribute>")

	var actual Attribute
	err = xml.Unmarshal(x, &actual)
	c.Assert(err, IsNil)
	c.Assert(actual, DeepEquals, expected)
}
