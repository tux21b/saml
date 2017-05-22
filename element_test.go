// +build ignore

package saml

import (
	"encoding/xml"

	"github.com/beevik/etree"
	. "gopkg.in/check.v1"
)

type ElementTest struct{}

var _ = Suite(&ElementTest{})

type X struct {
	ID        string         `xml:"ID,attr"`
	StringEl  string         `xml:"StringEl"`
	Signature *etree.Element `xml:"frob"`
	Value     string         `xml:",chardata"`
	Zero      string         `xml:",attr"`
}

func elementStr(el *etree.Element) string {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	rv, err := doc.WriteToString()
	if err != nil {
		panic(err)
	}
	return rv
}

func (s *ElementTest) TestElementMarshalUnmarshal(c *C) {
	const expectedXML = `<X ID="attr"><StringEl>str</StringEl><frob qux="quxxx"><blarg/><blaz/></frob>vvv</X>`
	x := X{
		ID:       "attr",
		StringEl: "str",
		Value:    "vvv",
	}

	sigEl := etree.NewElement("frob")
	sigEl.AddChild(etree.NewElement("blarg"))
	sigEl.AddChild(etree.NewElement("blaz"))
	sigEl.CreateAttr("qux", "quxxx")
	x.Signature = sigEl

	el, err := MarshalElement(&x)
	c.Assert(err, IsNil)
	c.Assert(elementStr(el), DeepEquals, expectedXML)

	el, err = MarshalElement(x)
	c.Assert(err, IsNil)
	c.Assert(elementStr(el), DeepEquals, expectedXML)

	/*
		x2 := X{}
		err = xml.Unmarshal(buf, &x2)
		c.Assert(err, IsNil)
		c.Assert(x, DeepEquals, x2)

		buf, err = xml.Marshal(x2)
		c.Assert(err, IsNil)
		c.Assert(string(buf), Equals, expectedXML)
	*/
}

func (s *ElementTest) TestElementNotPresent(c *C) {
	const expectedXML = `<X ID="attr"><StringEl>string</StringEl>value</X>`
	x := X{
		ID:       "attr",
		StringEl: "string",
		Value:    "value",
	}

	buf, err := xml.Marshal(x)
	c.Assert(err, IsNil)
	c.Assert(string(buf), Equals, expectedXML)

	x2 := X{}
	err = xml.Unmarshal(buf, &x2)
	c.Assert(err, IsNil)
	c.Assert(x, DeepEquals, x2)

	buf, err = xml.Marshal(x2)
	c.Assert(err, IsNil)
	c.Assert(string(buf), Equals, expectedXML)
}

type XX struct {
	Signature *etree.Element `xml:"ignored ignored"`
	Foo       string         `xml:"ns:tag"`
	Buf       []byte
	Buf2      []byte `xml:",attr"`
}

func (s *ElementTest) TestNamespace(c *C) {
	const expectedXML = `<XX><b:frob xmlns:b="blarg" qux="quxxx"><b:blarg/><b:blaz/></b:frob><ns:tag>value</ns:tag><Buf>QUFBQQ==</Buf></XX>`

	el := etree.NewElement("b:frob")
	el.CreateAttr("xmlns:b", "blarg")
	el.AddChild(etree.NewElement("b:blarg"))
	el.AddChild(etree.NewElement("b:blaz"))
	el.CreateAttr("qux", "quxxx")

	xx := XX{Signature: el, Foo: "value", Buf: []byte("AAAA"), Buf2: []byte("BBBB")}

	el, err := MarshalElement(xx)
	c.Assert(err, IsNil)
	//c.Assert(elementStr(el), Equals, expectedXML)

	buf, err := xml.Marshal(xx)
	c.Assert(err, IsNil)
	c.Assert(string(buf), Equals, "XXX")

	x2 := XX{}
	err = xml.Unmarshal([]byte(elementStr(el)), &x2)
	c.Assert(err, IsNil)
	c.Assert(xx, DeepEquals, x2)

	/*
		buf, err = xml.Marshal(x2)
		c.Assert(err, IsNil)
		c.Assert(elementStr(buf), Equals, expectedXML)
	*/
}
