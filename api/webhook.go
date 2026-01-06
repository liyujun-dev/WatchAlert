package api

import (
	"watchAlert/alert/process"
	ctx2 "watchAlert/internal/ctx"
	"watchAlert/internal/models"
	"watchAlert/internal/services"
	"watchAlert/internal/types"
	"watchAlert/pkg/provider"
	"watchAlert/pkg/response"
	"watchAlert/pkg/tools"

	"github.com/gin-gonic/gin"
)

type webhookController struct{}

var WebhookController = new(webhookController)

// ReceiveWebhook 接收外部系统的 Webhook 数据
// POST /webhook/:datasourceId
func (webhookController) ReceiveWebhook(ctx *gin.Context) {
	datasourceId := ctx.Param("datasourceId")

	// 1. 查询数据源配置
	datasource, err := services.DatasourceService.Get(&types.RequestDatasourceQuery{
		ID: datasourceId,
	})
	if err != nil {
		response.Fail(ctx, "数据源不存在", "failed")
		return
	}

	ds := datasource.(models.AlertDataSource)

	// 验证数据源类型
	if ds.Type != "Webhook" {
		response.Fail(ctx, "数据源类型错误", "该数据源不是 Webhook 类型")
		return
	}

	// 2. 解析 JSON body
	var payload map[string]interface{}
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		response.Fail(ctx, "数据格式错误", err.Error())
		return
	}

	// 3. 验证必需字段：faultCenterId
	faultCenterId, ok := payload["faultCenterId"].(string)
	if !ok || faultCenterId == "" {
		response.Fail(ctx, "缺少必需字段 faultCenterId", "failed")
		return
	}

	// 4. 创建 Webhook 客户端
	client, err := provider.NewWebhookClient(ds)
	if err != nil {
		response.Fail(ctx, "创建客户端失败", "failed")
		return
	}

	// 5. 字段映射
	mappedData, err := client.MapFields(payload)
	if err != nil {
		response.Fail(ctx, "字段映射失败", "failed")
		return
	}

	// 6. 生成指纹
	fingerprint := client.GenerateFingerprint(payload, datasourceId, faultCenterId)

	// 7. 构建 AlertCurEvent
	event := buildAlertEventFromWebhook(ds, mappedData, faultCenterId, fingerprint)

	// 8. 推送到故障中心（Redis）
	process.PushEventToFaultCenter(ctx2.DO(), &event)

	response.Success(ctx, nil, "接收成功")
}

// buildAlertEventFromWebhook 从 Webhook 数据构建告警事件
func buildAlertEventFromWebhook(ds models.AlertDataSource, data map[string]interface{}, faultCenterId, fingerprint string) models.AlertCurEvent {
	// 获取 labels
	labels := make(map[string]interface{})
	if l, ok := data["labels"].(map[string]interface{}); ok {
		labels = l
	}

	// 构建事件
	event := models.AlertCurEvent{
		TenantId:       ds.TenantId,
		EventId:        tools.RandId(),
		DatasourceType: "Webhook",
		DatasourceId:   ds.ID,
		Fingerprint:    fingerprint,
		Severity:       getStringValue(data, "severity", "P2"),
		RuleName:       getStringValue(data, "rule_name", "Webhook Alert"),
		RuleId:         "webhook_" + ds.ID, // 虚拟规则 ID
		Labels:         labels,
		Annotations:    getStringValue(data, "annotations", ""),
		FaultCenterId:  faultCenterId,
		Status:         models.StateAlerting, // Webhook 直接告警
		ForDuration:    0,                    // 立即触发
		EvalInterval:   0,
	}

	return event
}

// getStringValue 从 map 中获取字符串值，如果不存在则返回默认值
func getStringValue(data map[string]interface{}, key, defaultValue string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return defaultValue
}
