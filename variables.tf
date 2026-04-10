variable "workload_name" {
  type        = string
  default     = "appsvc"
  description = "Suffix used by the source Bicep template. Terraform uses system/environment inputs directly for naming."
}

variable "location" {
  type        = string
  description = "Azure region for the deployment."
}

variable "environment_name" {
  type        = string
  description = "Friendly environment name."
}

variable "system_abbreviation" {
  type        = string
  description = "Owning system abbreviation."
}

variable "environment_abbreviation" {
  type        = string
  description = "Lifecycle environment abbreviation."
}

variable "instance_number" {
  type        = string
  description = "Deterministic instance suffix."
}

variable "workload_description" {
  type        = string
  description = "Optional workload descriptor that participates in naming."
  default     = ""
}

variable "deploy_ase_v3" {
  type        = bool
  default     = false
  description = "Whether to deploy an App Service Environment v3."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to resources."
}

variable "existing_log_analytics_id" {
  type        = string
  default     = null
  description = "Optional existing Log Analytics workspace resource ID."
}

variable "deploy_private_networking" {
  type        = bool
  default     = true
  description = "Whether to deploy private endpoints and private DNS assets."
}

variable "deploy_postgresql" {
  type        = bool
  default     = false
  description = "Whether to deploy PostgreSQL Flexible Server."
}

variable "spoke_network_config" {
  type        = any
  description = "Bicep-shaped spoke network configuration object."
}

variable "service_plan_config" {
  type        = any
  description = "Bicep-shaped App Service Plan configuration object."
}

variable "app_service_config" {
  type        = any
  description = "Bicep-shaped App Service configuration object."
}

variable "key_vault_config" {
  type        = any
  description = "Bicep-shaped Key Vault configuration object."
}

variable "app_insights_config" {
  type        = any
  description = "Bicep-shaped Application Insights configuration object."
}

variable "app_gateway_config" {
  type        = any
  description = "Bicep-shaped Application Gateway configuration object."
}

variable "front_door_config" {
  type        = any
  description = "Bicep-shaped Front Door configuration object."
}

variable "ase_config" {
  type        = any
  description = "Bicep-shaped App Service Environment configuration object."
}

variable "postgresql_admin_group_config" {
  type        = any
  description = "Microsoft Entra group used as PostgreSQL administrator."
}

variable "postgresql_config" {
  type        = any
  description = "Bicep-shaped PostgreSQL Flexible Server configuration object."
}

variable "log_analytics_config" {
  type        = any
  description = "Bicep-shaped Log Analytics configuration object."
}
