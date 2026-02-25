package extractor

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/clusterpulse/cluster-controller/pkg/utils"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Extractor handles field extraction from unstructured Kubernetes resources
type Extractor struct {
	log *logrus.Entry
}

// NewExtractor creates a new field extractor
func NewExtractor() *Extractor {
	return &Extractor{
		log: logrus.WithField("component", "field-extractor"),
	}
}

// ExtractFields extracts all configured fields from a resource
func (e *Extractor) ExtractFields(
	resource *unstructured.Unstructured,
	fields []types.CompiledField,
) (map[string]any, error) {

	result := make(map[string]any, len(fields))

	for _, field := range fields {
		value, err := e.extractField(resource.Object, &field)
		if err != nil {
			e.log.Debugf("Field extraction warning for %s: %v", field.Name, err)
			// Use default if available, otherwise nil
			if field.Default != nil {
				value = e.convertType(*field.Default, field.Type)
			}
		}
		result[field.Name] = value
	}

	return result, nil
}

// extractField extracts a single field value using the pre-parsed path segments
func (e *Extractor) extractField(obj map[string]any, field *types.CompiledField) (any, error) {
	rawValue, found, err := e.navigatePath(obj, field.PathSegments)
	if err != nil {
		return nil, err
	}

	if !found {
		if field.Default != nil {
			return e.convertType(*field.Default, field.Type), nil
		}
		return nil, nil
	}

	return e.convertValue(rawValue, field.Type)
}

// navigatePath traverses the object using pre-parsed path segments
func (e *Extractor) navigatePath(obj any, segments []string) (any, bool, error) {
	current := obj

	for _, segment := range segments {
		if current == nil {
			return nil, false, nil
		}

		// Handle array index notation [n]
		if strings.HasPrefix(segment, "[") && strings.HasSuffix(segment, "]") {
			indexStr := segment[1 : len(segment)-1]
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				return nil, false, fmt.Errorf("invalid array index: %s", indexStr)
			}

			arr, ok := current.([]any)
			if !ok {
				return nil, false, nil
			}
			if index < 0 || index >= len(arr) {
				return nil, false, nil
			}
			current = arr[index]
			continue
		}

		// Handle map navigation
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false, nil
		}

		val, exists := m[segment]
		if !exists {
			return nil, false, nil
		}
		current = val
	}

	return current, true, nil
}

// convertValue converts a raw value to the specified type
func (e *Extractor) convertValue(value any, fieldType string) (any, error) {
	if value == nil {
		return nil, nil
	}

	switch fieldType {
	case types.FieldTypeString:
		return e.toString(value), nil
	case types.FieldTypeInteger:
		return e.toInteger(value)
	case types.FieldTypeFloat:
		return e.toFloat(value)
	case types.FieldTypeBoolean:
		return e.toBoolean(value)
	case types.FieldTypeQuantity:
		return e.toQuantityBytes(value)
	case types.FieldTypeTimestamp:
		return e.toTimestamp(value)
	case types.FieldTypeArrayLength:
		return e.toArrayLength(value)
	default:
		return e.toString(value), nil
	}
}

// convertType converts a string default value to the appropriate type
func (e *Extractor) convertType(value string, fieldType string) any {
	switch fieldType {
	case types.FieldTypeInteger:
		if v, err := strconv.ParseInt(value, 10, 64); err == nil {
			return v
		}
		return int64(0)
	case types.FieldTypeFloat:
		if v, err := strconv.ParseFloat(value, 64); err == nil {
			return v
		}
		return float64(0)
	case types.FieldTypeBoolean:
		return strings.ToLower(value) == "true"
	case types.FieldTypeQuantity:
		return utils.ParseMemory(value)
	default:
		return value
	}
}

// toString converts any value to string
func (e *Extractor) toString(value any) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// toInteger converts a value to int64
func (e *Extractor) toInteger(value any) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to integer", value)
	}
}

// toFloat converts a value to float64
func (e *Extractor) toFloat(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case int64:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float", value)
	}
}

// toBoolean converts a value to bool
func (e *Extractor) toBoolean(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		return strings.ToLower(v) == "true" || v == "1", nil
	case float64:
		return v != 0, nil
	case int64:
		return v != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to boolean", value)
	}
}

// toQuantityBytes parses Kubernetes quantity strings to bytes
func (e *Extractor) toQuantityBytes(value any) (int64, error) {
	str := e.toString(value)
	if str == "" {
		return 0, nil
	}

	// Handle CPU quantities (return millicores * 1000 for storage as int)
	if strings.HasSuffix(str, "m") && !strings.HasSuffix(str, "Mi") {
		// This is millicores, parse as CPU
		return int64(utils.ParseCPU(str) * 1000), nil
	}

	// Use existing memory parser for byte quantities
	return utils.ParseMemory(str), nil
}

// toTimestamp parses RFC3339 timestamps
func (e *Extractor) toTimestamp(value any) (string, error) {
	str := e.toString(value)
	if str == "" {
		return "", nil
	}

	// Validate it's a valid timestamp
	_, err := time.Parse(time.RFC3339, str)
	if err != nil {
		// Try alternative formats
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z"} {
			if _, err := time.Parse(layout, str); err == nil {
				return str, nil
			}
		}
		return "", fmt.Errorf("invalid timestamp format: %s", str)
	}

	return str, nil
}

// toArrayLength returns the length of an array
func (e *Extractor) toArrayLength(value any) (int64, error) {
	if value == nil {
		return 0, nil
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		return int64(rv.Len()), nil
	case reflect.Map:
		return int64(rv.Len()), nil
	default:
		return 0, fmt.Errorf("cannot get length of %T", value)
	}
}

// ExtractResourceIdentity extracts standard identity fields from a resource
func (e *Extractor) ExtractResourceIdentity(resource *unstructured.Unstructured) (namespace, name string, labels map[string]string) {
	namespace = resource.GetNamespace()
	name = resource.GetName()
	labels = resource.GetLabels()
	return
}

// BuildResourceID creates a unique identifier for a resource
func (e *Extractor) BuildResourceID(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}
