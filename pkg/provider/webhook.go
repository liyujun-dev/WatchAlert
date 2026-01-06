package provider

import (
	"fmt"
	"strconv"
	"strings"
	"watchAlert/internal/models"
	"watchAlert/pkg/tools"
)

const WebhookDsProviderName = "Webhook"

type WebhookClient struct {
	datasource models.AlertDataSource
}

func NewWebhookClient(ds models.AlertDataSource) (*WebhookClient, error) {
	return &WebhookClient{datasource: ds}, nil
}

func (c *WebhookClient) Check() (bool, error) {
	// Webhook 不需要主动检查，有配置即可
	return true, nil
}

// MapFields 字段映射转换
func (c *WebhookClient) MapFields(sourceData map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	mapping := c.datasource.WebhookConfig.FieldMapping

	for sourceField, targetField := range mapping {
		value, ok := sourceData[sourceField]
		if !ok {
			continue
		}

		// 支持嵌套字段，如 labels.host
		if strings.HasPrefix(targetField, "labels.") {
			labelKey := strings.TrimPrefix(targetField, "labels.")
			if result["labels"] == nil {
				result["labels"] = make(map[string]interface{})
			}
			result["labels"].(map[string]interface{})[labelKey] = value
		} else {
			result[targetField] = value
		}
	}

	return result, nil
}

// GenerateFingerprint 根据配置的字段生成指纹
func (c *WebhookClient) GenerateFingerprint(sourceData map[string]interface{}, datasourceId, faultCenterId string) string {
	fingerprintFields := c.datasource.WebhookConfig.FingerprintFields

	// 如果 payload 中直接提供了 fingerprint，使用它
	if fp, ok := sourceData["fingerprint"].(string); ok && fp != "" {
		return fp
	}

	// 构建指纹数据
	fingerprintData := make(map[string]interface{})
	fingerprintData["datasource_id"] = datasourceId
	fingerprintData["fault_center_id"] = faultCenterId

	// 如果配置了指纹字段，使用配置的字段
	if len(fingerprintFields) > 0 {
		for _, field := range fingerprintFields {
			if value, ok := sourceData[field]; ok {
				fingerprintData[field] = value
			}
		}
	} else {
		// 未配置则使用所有字段（排除 faultCenterId 和一些元数据）
		for k, v := range sourceData {
			if k != "faultCenterId" && k != "fingerprint" {
				fingerprintData[k] = v
			}
		}
	}

	return calculateFingerprint(fingerprintData)
}

// calculateFingerprint 计算指纹
func calculateFingerprint(data map[string]interface{}) string {
	if len(data) == 0 {
		return strconv.FormatUint(tools.HashNew(), 10)
	}

	var result uint64
	for key, value := range data {
		sum := tools.HashNew()
		sum = tools.HashAdd(sum, key)
		sum = tools.HashAdd(sum, fmt.Sprintf("%v", value))
		result ^= sum
	}

	return strconv.FormatUint(result, 10)
}
