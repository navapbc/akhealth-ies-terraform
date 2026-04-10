variable "scope" {
  type = string
}

variable "role_assignments" {
  type = list(object({
    key                                = optional(string)
    roleDefinitionId                   = optional(string)
    roleDefinitionName                 = optional(string)
    principalId                        = string
    principalType                      = optional(string)
    description                        = optional(string)
    condition                          = optional(string)
    conditionVersion                   = optional(string)
    delegatedManagedIdentityResourceId = optional(string)
    name                               = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for assignment in var.role_assignments :
      ((assignment.roleDefinitionId != null) != (assignment.roleDefinitionName != null))
    ])
    error_message = "Each role assignment must set exactly one of roleDefinitionId or roleDefinitionName."
  }

  validation {
    condition = alltrue([
      for assignment in var.role_assignments :
      assignment.key == null || trimspace(assignment.key) != ""
    ])
    error_message = "Role assignment keys must be omitted or non-empty."
  }

  validation {
    condition = length(compact([
      for assignment in var.role_assignments :
      assignment.key
      ])) == length(distinct(compact([
        for assignment in var.role_assignments :
        assignment.key
    ])))
    error_message = "Role assignment keys must be unique when provided."
  }
}
