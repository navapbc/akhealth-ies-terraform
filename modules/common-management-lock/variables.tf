variable "scope" {
  type = string
}

variable "name_suffix" {
  type = string
}

variable "lock" {
  type = object({
    kind  = string
    name  = optional(string)
    notes = optional(string)
  })
  default = null
}
