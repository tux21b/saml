// +build ignore

package saml

import (
	"log"
	"reflect"

	"strings"

	"github.com/beevik/etree"
)

func deref(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if !v.IsNil() {
			return v.Elem()
		}
	}
	return v
}

type fieldTag []string

func (ft fieldTag) Name() string {
	return ft[0]
}
func (ft fieldTag) IsAttr() bool {
	for _, v := range ft[1:] {
		if v == "attr" {
			return true
		}
	}
	return false
}
func (ft fieldTag) IsCharData() bool {
	for _, v := range ft[1:] {
		if v == "chardata" {
			return true
		}
	}
	return false
}

func MarshalElement(v interface{}) (*etree.Element, error) {
	val := deref(reflect.ValueOf(v))
	el := etree.NewElement(val.Type().Name())
	if err := marshalStruct(val, el); err != nil {
		return nil, err
	}
	return el, nil
}

var etreeElementType = reflect.TypeOf(etree.Element{})

func marshalElement(val reflect.Value, el *etree.Element) error {
	val = deref(val)
	if val.Type() == etreeElementType {
		*el = *(val.Addr().Interface().(*etree.Element))
		return nil
	}

	// marshal a struct
	if val.Kind() == reflect.Struct {
		if err := marshalStruct(val, el); err != nil {
			return err
		}
	}

	// marshal a scalar
	if err := marshalScalar(val, el); err != nil {
		return err
	}
	return nil
}

func marshalStruct(val reflect.Value, el *etree.Element) error {
	val = deref(val)

	for i := 0; i < val.Type().NumField(); i++ {
		f := val.Type().Field(i)
		tags := fieldTag(strings.Split(f.Tag.Get("xml"), ","))
		if tags[0] == "-" {
			continue
		}
		fieldName := f.Name
		if tags[0] != "" {
			fieldName = tags[0]
		}
		log.Printf("fieldName: %q", fieldName)

		childVal := val.Field(i)
		if childVal.Kind() == reflect.Ptr || childVal.Kind() == reflect.Interface {
			if childVal.IsNil() {
				continue
			}
		}

		childVal = deref(childVal)
		if childVal.Type().Comparable() && reflect.Zero(childVal.Type()).Interface() == childVal.Interface() {
			continue
		}

		if tags.IsAttr() {
			el.CreateAttr(fieldName, marshalScalarAsString(childVal))
			continue
		}

		if tags.IsCharData() {
			el.AddChild(etree.NewCharData(marshalScalarAsString(childVal)))
			continue
		}

		// marshal a slice
		if childVal.Kind() == reflect.Slice && childVal.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < childVal.Len(); i++ {
				childElemVal := childVal.Index(i)
				childEl := etree.NewElement(fieldName)
				if err := marshalElement(childElemVal, childEl); err != nil {
					return err
				}
				el.AddChild(childEl)
			}
			continue
		}
		childEl := etree.NewElement(fieldName)
		if err := marshalElement(childVal, childEl); err != nil {
			return err
		}
		el.AddChild(childEl)
	}

	return nil
}

func marshalScalarAsString(val reflect.Value) string {
	/*
		if val.Kind() == reflect.Slice && val.Type().Elem().Kind() == reflect.Uint8 {
			return base64.StdEncoding.EncodeToString(val.Interface().([]byte))
		}
	*/
	return val.String()
}

func marshalScalar(val reflect.Value, el *etree.Element) error {

	el.SetText(marshalScalarAsString(val))
	return nil
}
