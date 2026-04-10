locals {
  region_abbreviations = {
    eastus         = "eus"
    eastus2        = "eus2"
    westus         = "wus"
    westus2        = "wus2"
    westus3        = "wus3"
    centralus      = "cus"
    northcentralus = "ncus"
    southcentralus = "scus"
    westcentralus  = "wcus"
    global         = "global"
  }

  region_abbreviation = lookup(local.region_abbreviations, var.location, replace(var.location, " ", ""))
  workload_segment    = trimspace(var.workload_description) == "" ? "" : "-${var.workload_description}"
  name                = substr("afd-security-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 128)
}

resource "azurerm_cdn_frontdoor_security_policy" "this" {
  name                     = local.name
  cdn_frontdoor_profile_id = var.profile_resource_id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = var.waf_policy_resource_id

      association {
        patterns_to_match = var.security_patterns_to_match

        dynamic "domain" {
          for_each = toset(var.domain_resource_ids)
          content {
            cdn_frontdoor_domain_id = domain.value
          }
        }
      }
    }
  }
}
