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
  app_image         = "bkimminich/juice-shop:v18.0.0"
  ca_secret_arn     = "arn:aws:secretsmanager:ap-northeast-2:000000000000:secret:ca-AbCdEf"
  time_sync         = "true"
}

run "app_is_private_and_hardened" {
  # Hop limit 1 is what stops the container reaching instance credentials:
  # measured in Phase 6, the host got 200 and the container was blocked.
  assert {
    condition     = aws_instance.app.metadata_options[0].http_tokens == "required" && aws_instance.app.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 must be required with a hop limit of 1 (SR-02, F6)."
  }
  assert {
    condition     = aws_instance.app.root_block_device[0].encrypted == true
    error_message = "The root volume must be encrypted (AWS-0131)."
  }
}
