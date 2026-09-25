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
  instance_type     = "t3.micro"
  app_private_ip    = "10.20.8.10"
  ca_secret_arn     = "arn:aws:secretsmanager:ap-northeast-2:000000000000:secret:ca-AbCdEf"
  cwagent_install   = "true"
  time_sync         = "true"
}

run "instance_is_hardened" {
  assert {
    condition     = aws_instance.waf.metadata_options[0].http_tokens == "required" && aws_instance.waf.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 must be required with a hop limit of 1 (SR-02, F6)."
  }
  assert {
    condition     = aws_instance.waf.root_block_device[0].encrypted == true
    error_message = "The root volume must be encrypted (AWS-0131)."
  }
  assert {
    condition     = aws_eip.waf.instance == aws_instance.waf.id
    error_message = "The Elastic IP must stay attached to the WAF."
  }
}

run "logs_are_kept_fourteen_days" {
  assert {
    condition     = aws_cloudwatch_log_group.this.retention_in_days == 14
    error_message = "Log retention must be 14 days (NFR-06, F7)."
  }
}
