variable "scope" {
  type = string
}

variable "role_assignments" {
  type = list(object({
    roleDefinitionIdOrName             = string
    principalId                        = string
    principalType                      = optional(string)
    description                        = optional(string)
    condition                          = optional(string)
    conditionVersion                   = optional(string)
    delegatedManagedIdentityResourceId = optional(string)
    name                               = optional(string)
  }))
  default = []
}
