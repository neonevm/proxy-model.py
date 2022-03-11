// AWS specific
variable "aws_subnet" {
  type    = string
  default = "default"
}

variable "allow_list" {
  type = list(string)
}

variable "instance_type" {
  type = string
}

variable "ami" {
  type = string
}

// software sprcific
variable "branch" {
  type = string
}

variable "neon_evm_revision" {
  type = string
}

variable "proxy_model_revision" {
  type = string
}

