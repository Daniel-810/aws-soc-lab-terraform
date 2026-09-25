# Mocked AWS provider: no credentials, no resources, no cost.
# Only values the code sets can be asserted: the mock fills anything left
# unset (a key pair name, a public address flag) with random data.

# Policy documents are rendered by the provider; the mock returns a random
# string, which the role resource rejects. A valid empty policy stands in.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  subnet_id         = "subnet-0123456789abcdef0"
  security_group_id = "sg-0123456789abcdef0"
  home_net          = "10.20.0.0/16"
  rules             = "drop http any any -> $HOME_NET any (msg:\"t\"; sid:1; rev:1;)"
  cwagent_install   = "true"
  time_sync         = "true"
}

run "instance_can_forward_and_is_hardened" {
  assert {
    condition     = aws_instance.this.source_dest_check == false
    error_message = "Forwarding needs the source/destination check off (F13)."
  }
  assert {
    condition     = aws_instance.this.metadata_options[0].http_tokens == "required" && aws_instance.this.root_block_device[0].encrypted == true
    error_message = "IMDSv2 and an encrypted root volume are required."
  }
}

run "home_net_must_be_a_range" {
  command = plan
  variables {
    home_net = "10.20.0.1"
  }
  expect_failures = [var.home_net]
}
