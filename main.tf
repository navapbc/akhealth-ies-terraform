resource "azurerm_resource_group" "spoke" {
  name     = local.resource_group_name
  location = var.location
  tags     = var.tags
}

module "log_analytics_workspace" {
  count  = trimspace(var.existing_log_analytics_id == null ? "" : var.existing_log_analytics_id) == "" ? 1 : 0
  source = "./modules/log-analytics-workspace"

  resource_group_name                               = azurerm_resource_group.spoke.name
  system_abbreviation                               = var.system_abbreviation
  environment_abbreviation                          = var.environment_abbreviation
  instance_number                                   = var.instance_number
  workload_description                              = var.workload_description
  location                                          = var.location
  tags                                              = var.tags
  sku                                               = var.log_analytics_config.sku
  retention_in_days                                 = var.log_analytics_config.retentionInDays
  enable_log_access_using_only_resource_permissions = var.log_analytics_config.enableLogAccessUsingOnlyResourcePermissions
  disable_local_auth                                = var.log_analytics_config.disableLocalAuth
  public_network_access_for_ingestion               = var.log_analytics_config.publicNetworkAccessForIngestion
  public_network_access_for_query                   = var.log_analytics_config.publicNetworkAccessForQuery
  lock                                              = try(var.log_analytics_config.lock, null)
  role_assignments                                  = try(var.log_analytics_config.roleAssignments, [])
  diagnostic_settings                               = try(var.log_analytics_config.diagnosticSettings, [])
}

module "network" {
  source = "./modules/network"

  resource_group_name                         = azurerm_resource_group.spoke.name
  system_abbreviation                         = var.system_abbreviation
  environment_abbreviation                    = var.environment_abbreviation
  instance_number                             = var.instance_number
  workload_description                        = var.workload_description
  location                                    = var.location
  deploy_ase_v3                               = var.deploy_ase_v3
  deploy_private_networking                   = local.private_networking_enabled
  enable_egress_lockdown                      = var.spoke_network_config.enableEgressLockdown
  vnet_spoke_address_space                    = var.spoke_network_config.vnetAddressSpace
  subnet_spoke_appsvc_address_space           = var.spoke_network_config.appSvcSubnetAddressSpace
  subnet_spoke_private_endpoint_address_space = try(var.spoke_network_config.privateEndpointSubnetAddressSpace, "")
  application_gateway_config                  = try(var.spoke_network_config.applicationGatewayConfig, null)
  postgresql_private_access_config            = try(var.spoke_network_config.postgreSqlPrivateAccessConfig, null)
  egress_firewall_config                      = try(var.spoke_network_config.egressFirewallConfig, null)
  networking_option                           = var.spoke_network_config.ingressOption
  deploy_postgresql_private_access            = local.postgresql_private_networking_enabled
  log_analytics_workspace_id                  = local.resolved_log_analytics_workspace_id
  hub_peering_config                          = try(var.spoke_network_config.hubPeeringConfig, null)
  dns_servers                                 = try(var.spoke_network_config.dnsServers, [])
  ddos_protection_plan_resource_id            = try(var.spoke_network_config.ddosProtectionPlanResourceId, null)
  vnet_diagnostic_settings                    = try(var.spoke_network_config.diagnosticSettings, [])
  vnet_lock                                   = try(var.spoke_network_config.lock, null)
  disable_bgp_route_propagation               = var.spoke_network_config.disableBgpRoutePropagation
  vnet_role_assignments                       = try(var.spoke_network_config.roleAssignments, [])
  vnet_encryption                             = var.spoke_network_config.encryption
  vnet_encryption_enforcement                 = var.spoke_network_config.encryptionEnforcement
  flow_timeout_in_minutes                     = var.spoke_network_config.flowTimeoutInMinutes
  enable_vm_protection                        = var.spoke_network_config.enableVmProtection
  enable_private_endpoint_vnet_policies       = var.spoke_network_config.enablePrivateEndpointVNetPolicies
  virtual_network_bgp_community               = try(var.spoke_network_config.bgpCommunity, null)
  tags                                        = var.tags
}

module "app_service_environment" {
  count  = var.deploy_ase_v3 ? 1 : 0
  source = "./modules/app-service-environment"

  resource_group_name          = azurerm_resource_group.spoke.name
  system_abbreviation          = var.system_abbreviation
  environment_abbreviation     = var.environment_abbreviation
  instance_number              = var.instance_number
  workload_description         = var.workload_description
  location                     = var.location
  subnet_resource_id           = module.network.snet_appsvc_resource_id
  cluster_settings             = try(var.ase_config.clusterSettings, [])
  dedicated_host_count         = try(var.ase_config.dedicatedHostCount, null)
  internal_load_balancing_mode = try(var.ase_config.internalLoadBalancingMode, null)
  zone_redundant               = try(var.ase_config.zoneRedundant, null)
  role_assignments             = try(var.ase_config.roleAssignments, [])
  diagnostic_settings          = try(var.ase_config.diagnosticSettings, [])
  lock                         = try(var.ase_config.lock, null)
  tags                         = var.tags
}

module "app_insights" {
  source = "./modules/app-insights"

  resource_group_name                 = azurerm_resource_group.spoke.name
  system_abbreviation                 = var.system_abbreviation
  environment_abbreviation            = var.environment_abbreviation
  instance_number                     = var.instance_number
  workload_description                = var.workload_description
  location                            = var.location
  workspace_resource_id               = local.resolved_log_analytics_workspace_id
  application_type                    = var.app_insights_config.applicationType
  public_network_access_for_ingestion = var.app_insights_config.publicNetworkAccessForIngestion
  public_network_access_for_query     = var.app_insights_config.publicNetworkAccessForQuery
  retention_in_days                   = var.app_insights_config.retentionInDays
  sampling_percentage                 = var.app_insights_config.samplingPercentage
  disable_local_auth                  = var.app_insights_config.disableLocalAuth
  disable_ip_masking                  = var.app_insights_config.disableIpMasking
  force_customer_storage_for_profiler = var.app_insights_config.forceCustomerStorageForProfiler
  lock                                = try(var.app_insights_config.lock, null)
  role_assignments                    = try(var.app_insights_config.roleAssignments, [])
  diagnostic_settings                 = try(var.app_insights_config.diagnosticSettings, [])
  tags                                = var.tags
}

module "app_service_plan" {
  count  = local.deploy_app_service_plan ? 1 : 0
  source = "./modules/app-service-plan"

  resource_group_name                 = azurerm_resource_group.spoke.name
  system_abbreviation                 = var.system_abbreviation
  environment_abbreviation            = var.environment_abbreviation
  instance_number                     = var.instance_number
  workload_description                = var.workload_description
  location                            = var.location
  sku_name                            = var.service_plan_config.sku
  sku_capacity                        = var.service_plan_config.skuCapacity
  service_plan_kind                   = var.service_plan_config.kind
  workload_kind                       = var.app_service_config.kind
  app_service_environment_resource_id = var.deploy_ase_v3 ? module.app_service_environment[0].resource_id : null
  per_site_scaling                    = var.service_plan_config.perSiteScaling
  maximum_elastic_worker_count        = var.service_plan_config.maximumElasticWorkerCount
  zone_redundant                      = var.service_plan_config.zoneRedundant
  diagnostic_settings                 = try(var.service_plan_config.diagnosticSettings, [])
  lock                                = try(var.service_plan_config.lock, null)
  role_assignments                    = try(var.service_plan_config.roleAssignments, [])
  tags                                = var.tags
}

module "web_app" {
  source = "./modules/web-app"

  resource_group_name                             = azurerm_resource_group.spoke.name
  system_abbreviation                             = var.system_abbreviation
  environment_abbreviation                        = var.environment_abbreviation
  instance_number                                 = var.instance_number
  workload_description                            = var.workload_description
  location                                        = var.location
  kind                                            = var.app_service_config.kind
  service_plan_kind                               = var.service_plan_config.kind
  server_farm_resource_id                         = local.resolved_app_service_plan_resource_id
  site_config                                     = var.app_service_config.siteConfig
  https_only                                      = var.app_service_config.httpsOnly
  client_affinity_enabled                         = var.app_service_config.clientAffinityEnabled
  public_network_access                           = try(var.app_service_config.publicNetworkAccess, null)
  outbound_vnet_routing                           = try(var.app_service_config.outboundVnetRouting, null)
  managed_identities                              = try(var.app_service_config.managedIdentities, null)
  key_vault_access_identity_resource_id           = try(var.app_service_config.keyVaultAccessIdentityResourceId, null)
  virtual_network_subnet_resource_id              = local.web_app_private_networking_enabled && !try(var.service_plan_config.isCustomMode, false) ? module.network.snet_appsvc_resource_id : null
  enabled                                         = var.app_service_config.enabled
  disable_basic_publishing_credentials            = try(var.app_service_config.disableBasicPublishingCredentials, false)
  configs                                         = try(var.app_service_config.configs, [])
  solution_application_insights_connection_string = module.app_insights.connection_string
  function_host_storage_account = try(one([
    for config in try(var.app_service_config.configs, []) :
    config.existingFunctionHostStorageAccount if try(config.name, "") == "appsettings" && try(config.existingFunctionHostStorageAccount, null) != null
  ]), null)
  enable_default_private_endpoint                = local.web_app_private_networking_enabled
  default_private_endpoint_subnet_resource_id    = module.network.snet_pe_resource_id
  default_private_dns_zone_virtual_network_links = local.spoke_private_dns_zone_links
  role_assignments                               = try(var.app_service_config.roleAssignments, [])
  diagnostic_settings                            = try(var.app_service_config.diagnosticSettings, [])
  lock                                           = try(var.app_service_config.lock, null)
  reserved                                       = try(var.app_service_config.reserved, false)
  tags                                           = var.tags
}

module "front_door_waf_policy" {
  count  = local.use_front_door_ingress ? 1 : 0
  source = "./modules/front-door-waf-policy"

  resource_group_name      = azurerm_resource_group.spoke.name
  system_abbreviation      = var.system_abbreviation
  environment_abbreviation = var.environment_abbreviation
  instance_number          = var.instance_number
  workload_description     = var.workload_description
  config                   = var.front_door_config
  tags                     = var.tags
}

module "front_door" {
  count  = local.use_front_door_ingress ? 1 : 0
  source = "./modules/front-door"

  resource_group_name         = azurerm_resource_group.spoke.name
  system_abbreviation         = var.system_abbreviation
  environment_abbreviation    = var.environment_abbreviation
  instance_number             = var.instance_number
  workload_description        = var.workload_description
  location                    = "global"
  config                      = var.front_door_config
  workload_origin_host_name   = module.web_app.default_hostname
  workload_origin_resource_id = module.web_app.resource_id
  workload_origin_location    = module.web_app.location
  tags                        = var.tags
}

module "front_door_security_policy" {
  count  = local.use_front_door_ingress ? 1 : 0
  source = "./modules/front-door-security-policy"

  system_abbreviation        = var.system_abbreviation
  environment_abbreviation   = var.environment_abbreviation
  instance_number            = var.instance_number
  workload_description       = var.workload_description
  location                   = var.location
  profile_resource_id        = module.front_door[0].resource_id
  waf_policy_resource_id     = module.front_door_waf_policy[0].resource_id
  domain_resource_ids        = module.front_door[0].afd_endpoint_resource_ids
  security_patterns_to_match = try(var.front_door_config.securityPatternsToMatch, ["/*"])
}

module "application_gateway" {
  count  = local.use_application_gateway_ingress ? 1 : 0
  source = "./modules/application-gateway"

  resource_group_name              = azurerm_resource_group.spoke.name
  system_abbreviation              = var.system_abbreviation
  environment_abbreviation         = var.environment_abbreviation
  instance_number                  = var.instance_number
  workload_description             = var.workload_description
  location                         = var.location
  sku                              = var.app_gateway_config.sku
  capacity                         = var.app_gateway_config.capacity
  autoscale_min_capacity           = try(var.app_gateway_config.autoscaleMinCapacity, null)
  autoscale_max_capacity           = try(var.app_gateway_config.autoscaleMaxCapacity, null)
  enable_http2                     = try(var.app_gateway_config.enableHttp2, false)
  enable_fips                      = try(var.app_gateway_config.enableFips, false)
  availability_zones               = try(var.app_gateway_config.availabilityZones, [])
  firewall_policy_resource_id      = null
  gateway_ip_configurations        = try(var.app_gateway_config.gatewayIPConfigurations, [])
  frontend_ip_configurations       = try(var.app_gateway_config.frontendIPConfigurations, [])
  frontend_ports                   = try(var.app_gateway_config.frontendPorts, [])
  backend_address_pools            = try(var.app_gateway_config.backendAddressPools, [])
  backend_http_settings_collection = try(var.app_gateway_config.backendHttpSettingsCollection, [])
  probes                           = try(var.app_gateway_config.probes, [])
  http_listeners                   = try(var.app_gateway_config.httpListeners, [])
  request_routing_rules            = try(var.app_gateway_config.requestRoutingRules, [])
  managed_identities               = try(var.app_gateway_config.managedIdentities, null)
  role_assignments                 = try(var.app_gateway_config.roleAssignments, [])
  diagnostic_settings              = try(var.app_gateway_config.diagnosticSettings, [])
  lock                             = try(var.app_gateway_config.lock, null)
  tags                             = var.tags
}

module "key_vault" {
  source = "./modules/key-vault"

  resource_group_name                            = azurerm_resource_group.spoke.name
  system_abbreviation                            = var.system_abbreviation
  environment_abbreviation                       = var.environment_abbreviation
  instance_number                                = var.instance_number
  workload_description                           = var.workload_description
  location                                       = var.location
  sku                                            = var.key_vault_config.sku
  network_acls                                   = try(var.key_vault_config.networkAcls, null)
  soft_delete_retention_in_days                  = var.key_vault_config.softDeleteRetentionInDays
  enable_purge_protection                        = var.key_vault_config.enablePurgeProtection
  public_network_access                          = var.key_vault_config.publicNetworkAccess
  enable_vault_for_deployment                    = var.key_vault_config.enableVaultForDeployment
  enable_vault_for_template_deployment           = var.key_vault_config.enableVaultForTemplateDeployment
  enable_vault_for_disk_encryption               = var.key_vault_config.enableVaultForDiskEncryption
  create_mode                                    = try(var.key_vault_config.createMode, "default")
  secrets                                        = try(var.key_vault_config.secrets, [])
  keys                                           = try(var.key_vault_config.keys, [])
  enable_default_private_endpoint                = local.private_networking_enabled
  default_private_endpoint_subnet_resource_id    = module.network.snet_pe_resource_id
  default_private_dns_zone_virtual_network_links = local.postgresql_private_dns_zone_links
  diagnostic_settings                            = try(var.key_vault_config.diagnosticSettings, [])
  lock                                           = try(var.key_vault_config.lock, null)
  role_assignments                               = try(var.key_vault_config.roleAssignments, [])
  tags                                           = var.tags
}

module "postgresql" {
  count  = var.deploy_postgresql ? 1 : 0
  source = "./modules/postgresql-flexible-server"

  resource_group_name                    = azurerm_resource_group.spoke.name
  system_abbreviation                    = var.system_abbreviation
  environment_abbreviation               = var.environment_abbreviation
  instance_number                        = var.instance_number
  workload_description                   = var.postgresql_config.workloadDescription
  location                               = var.location
  administrator_group_object_id          = var.postgresql_admin_group_config.objectId
  administrator_group_display_name       = var.postgresql_admin_group_config.displayName
  administrator_group_tenant_id          = data.azurerm_client_config.current.tenant_id
  sku_name                               = var.postgresql_config.skuName
  tier                                   = var.postgresql_config.tier
  availability_zone                      = var.postgresql_config.availabilityZone
  high_availability_zone                 = var.postgresql_config.highAvailabilityZone
  high_availability                      = var.postgresql_config.highAvailability
  backup_retention_days                  = var.postgresql_config.backupRetentionDays
  geo_redundant_backup                   = var.postgresql_config.geoRedundantBackup
  storage_size_gb                        = var.postgresql_config.storageSizeGB
  auto_grow                              = var.postgresql_config.autoGrow
  engine_version                         = var.postgresql_config.version
  public_network_access                  = var.postgresql_config.publicNetworkAccess
  private_access_mode                    = var.postgresql_config.privateAccessMode
  delegated_subnet_resource_id           = local.postgresql_private_access_enabled ? module.network.snet_postgresql_resource_id : null
  private_dns_zone_virtual_network_links = local.postgresql_private_dns_zone_links
  databases                              = try(var.postgresql_config.databases, [])
  configurations                         = try(var.postgresql_config.configurations, [])
  diagnostic_settings                    = try(var.postgresql_config.diagnosticSettings, [])
  lock                                   = try(var.postgresql_config.lock, null)
  role_assignments                       = local.postgresql_role_assignments
  tags                                   = var.tags
}
