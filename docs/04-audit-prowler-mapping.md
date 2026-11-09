# 자체 감사 재점검 — ISMS-P, ISO 27001 매핑 (2026-11-09)

요약과 해석은 [`04-audit-prowler.md`](04-audit-prowler.md) 7절에 있다. 이 문서는 Prowler가 낸 요구사항별, 점검별 결과를 표로 옮긴 것이다. 계정 ID와 리소스 ID는 뺐고, 원본 보고서는 저장소에 넣지 않았다(`SR-10`).

| 항목 | 내용 |
|---|---|
| 일자 | 2026-11-09 |
| 도구 | Prowler 5.43.0 |
| 대상 | 서울 리전 + 전역 서비스. 랩은 09-25와 같은 조건(방식 B, 라우팅 켬)으로 배포 |
| 매핑 | Prowler에 들어 있는 `kisa_isms_p_2023_korean_aws`, `iso27001_2022_aws`를 그대로 썼다 |
| 실행된 점검 | 187개 |

## 1. 점수

| 기준 | 통과 | 실패 | 수동 | 통과율 (수동 제외) |
|---|---|---|---|---|
| 결과(리소스 단위) | 262 | 94 | 6 | **73.6%** |
| 점검 단위 (리소스 하나라도 실패면 실패) | 108 | 73 | 6 | **59.7%** |

실패 결과의 심각도: critical 3, high 16, medium 56, low 19

09-25 감사(조치 후)는 통과 264, 실패 110, 수동 7(리소스 단위)이었다. 실패가 110 → 94로 줄었지만, 이번에는 실행된 점검 수가 다르고(09-25 문서는 199개) 09-26 혼동된 대리인 조치 3건도 반영돼 있어서 차이의 원인을 하나씩 나누지는 않았다.

## 2. ISMS-P 2023 (요구사항별)

요구사항 97개 중 **자동 점검이 붙은 것 23개**: 실패 21, 통과 2. 나머지 74개는 자동 점검 결과가 없어 수동 확인(정책, 조직, 절차 영역이거나, 매핑된 점검의 대상 리소스가 이 계정에 없음).

판정 기준: 요구사항에 매핑된 점검 중 실패한 리소스가 하나라도 있으면 실패. Prowler 매핑은 2.x 보호대책 요구사항 위주이고, 1.x 관리체계와 3.x 개인정보 처리 단계는 대부분 수동이다.

| 요구사항 | 이름 | 판정 | 결과 통과 / 실패 | 실패한 점검 |
|---|---|---|---|---|
| 2.1.3 | 정보자산 관리 | ❌ 실패 | 0 / 1 | `organizations_tags_policies_enabled_and_attached` |
| 2.5.1 | 사용자 계정 관리 | ❌ 실패 | 44 / 4 | `iam_aws_attached_policy_no_administrative_privileges`, `iam_role_administratoraccess_policy`, `iam_securityaudit_role_created`, `iam_support_role_created` |
| 2.5.3 | 사용자 인증 | ❌ 실패 | 5 / 6 | `cloudtrail_bucket_requires_mfa_delete`, `iam_check_saml_providers_sts`, `iam_root_hardware_mfa_enabled`, `iam_user_hardware_mfa_enabled`, `s3_bucket_no_mfa_delete` |
| 2.5.4 | 비밀번호 관리 | ❌ 실패 | 6 / 1 | `iam_password_policy_expires_passwords_within_90_days_or_less` |
| 2.5.5 | 특수 계정 및 권한 관리 | ❌ 실패 | 44 / 5 | `iam_aws_attached_policy_no_administrative_privileges`, `iam_role_administratoraccess_policy`, `iam_root_hardware_mfa_enabled`, `iam_securityaudit_role_created`, `iam_support_role_created` |
| 2.5.6 | 접근권한 검토 | ❌ 실패 | 51 / 6 | `ec2_instance_internet_facing_with_instance_profile`, `iam_aws_attached_policy_no_administrative_privileges`, `iam_role_administratoraccess_policy`, `iam_securityaudit_role_created`, `iam_support_role_created` |
| 2.6.1 | 네트워크 접근 | ❌ 실패 | 124 / 11 | `ec2_instance_internet_facing_with_instance_profile`, `ec2_instance_public_ip`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `vpc_endpoint_for_ec2_enabled` |
| 2.6.2 | 정보시스템 접근 | ❌ 실패 | 77 / 2 | `ec2_instance_internet_facing_with_instance_profile` |
| 2.6.3 | 응용프로그램 접근 | ✅ 통과 | 3 / 0 | - |
| 2.6.4 | 데이터베이스 접근 | ✅ 통과 | 57 / 0 | - |
| 2.6.6 | 원격접근 통제 | ❌ 실패 | 36 / 4 | `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389` |
| 2.7.1 | 암호정책 적용 | ❌ 실패 | 10 / 1 | `ec2_instance_secrets_user_data` |
| 2.7.2 | 암호키 관리 | ❌ 실패 | 11 / 9 | `cloudtrail_kms_encryption_enabled`, `cloudwatch_log_group_kms_encryption_enabled`, `kms_cmk_not_deleted_unintentionally`, `s3_bucket_kms_encryption`, `secretsmanager_automatic_rotation_enabled`, `secretsmanager_secret_rotated_periodically` |
| 2.9.2 | 성능 및 장애관리 | ❌ 실패 | 9 / 8 | `ec2_instance_detailed_monitoring_enabled`, `kms_cmk_not_deleted_unintentionally`, `s3_bucket_cross_region_replication`, `vpc_different_regions`, `vpc_subnet_different_az` |
| 2.9.3 | 백업 및 복구관리 | ❌ 실패 | 4 / 9 | `backup_vaults_exist`, `ec2_ebs_volume_protected_by_backup_plan`, `ec2_ebs_volume_snapshots_exists`, `s3_bucket_lifecycle_enabled`, `s3_bucket_object_lock` |
| 2.9.4 | 로그 및 접속기록 관리 | ❌ 실패 | 9 / 18 | `bedrock_model_invocation_logging_enabled`, `cloudtrail_bucket_requires_mfa_delete`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_insights_exist`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudwatch_alarm_actions_alarm_state_configured`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_network_route_tables_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_group_retention_policy_specific_days_enabled`, `s3_bucket_server_access_logging_enabled` |
| 2.10.1 | 보안시스템 운영 | ❌ 실패 | 14 / 36 | `cloudtrail_bucket_requires_mfa_delete`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_insights_exist`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudwatch_alarm_actions_alarm_state_configured`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_network_route_tables_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_group_kms_encryption_enabled`, `cloudwatch_log_group_retention_policy_specific_days_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_log_metric_filter_aws_organizations_changes`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`, `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_unauthorized_api_calls`, `guardduty_is_enabled`, `inspector2_is_enabled`, `kms_cmk_not_deleted_unintentionally`, `macie_is_enabled`, `networkfirewall_in_all_vpc`, `securityhub_enabled` |
| 2.10.2 | 클라우드 보안 | ❌ 실패 | 239 / 75 | `account_maintain_different_contact_details_to_security_billing_and_operations`, `bedrock_guardrails_configured`, `bedrock_model_invocation_logging_enabled`, `bedrock_prompt_management_exists`, `cloudtrail_bucket_requires_mfa_delete`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_insights_exist`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudwatch_alarm_actions_alarm_state_configured`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_network_route_tables_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_group_kms_encryption_enabled`, `cloudwatch_log_group_retention_policy_specific_days_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_log_metric_filter_aws_organizations_changes`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`, `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_unauthorized_api_calls`, `config_recorder_all_regions_enabled`, `drs_job_exist`, `ec2_instance_internet_facing_with_instance_profile`, `ec2_instance_public_ip`, `ec2_instance_secrets_user_data`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `guardduty_is_enabled`, `iam_aws_attached_policy_no_administrative_privileges`, `iam_check_saml_providers_sts`, `iam_password_policy_expires_passwords_within_90_days_or_less`, `iam_role_administratoraccess_policy`, `iam_root_hardware_mfa_enabled`, `iam_securityaudit_role_created`, `iam_support_role_created`, `iam_user_hardware_mfa_enabled`, `inspector2_is_enabled`, `macie_is_enabled`, `networkfirewall_in_all_vpc`, `organizations_account_part_of_organizations`, `organizations_opt_out_ai_services_policy`, `organizations_scp_check_deny_regions`, `s3_bucket_event_notifications_enabled`, `s3_bucket_kms_encryption`, `s3_bucket_no_mfa_delete`, `s3_bucket_server_access_logging_enabled`, `secretsmanager_automatic_rotation_enabled`, `secretsmanager_secret_rotated_periodically`, `securityhub_enabled`, `ssmincidents_enabled_with_plans`, `vpc_endpoint_for_ec2_enabled` |
| 2.11.1 | 사고 예방 및 대응체계 구축 | ❌ 실패 | 0 / 2 | `iam_support_role_created`, `ssmincidents_enabled_with_plans` |
| 2.11.2 | 취약점 점검 및 조치 | ❌ 실패 | 0 / 1 | `inspector2_is_enabled` |
| 2.11.3 | 이상행위 분석 및 모니터링 | ❌ 실패 | 3 / 25 | `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_insights_exist`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudwatch_alarm_actions_alarm_state_configured`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_network_route_tables_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_log_metric_filter_aws_organizations_changes`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`, `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_unauthorized_api_calls`, `config_recorder_all_regions_enabled`, `s3_bucket_event_notifications_enabled` |
| 2.12.1 | 재해·재난 대비 안전조치 | ❌ 실패 | 4 / 10 | `backup_vaults_exist`, `drs_job_exist`, `ec2_ebs_volume_protected_by_backup_plan`, `ec2_ebs_volume_snapshots_exists`, `s3_bucket_lifecycle_enabled`, `s3_bucket_object_lock` |
| 2.12.2 | 재해 복구 시험 및 개선 | ❌ 실패 | 0 / 1 | `drs_job_exist` |

## 3. ISO/IEC 27001:2022 Annex A (통제별)

요구사항 88개 중 **자동 점검이 붙은 것 32개**: 실패 30, 통과 2. 나머지 56개는 자동 점검 결과가 없어 수동 확인(정책, 조직, 절차 영역이거나, 매핑된 점검의 대상 리소스가 이 계정에 없음).

같은 판정 기준. 대부분 A.8 기술적 통제에 매핑되고 A.5 조직적 통제 일부에도 걸린다.

| 요구사항 | 이름 | 판정 | 결과 통과 / 실패 | 실패한 점검 |
|---|---|---|---|---|
| A.5.1 | Policies for information security | ❌ 실패 | 0 / 1 | `securityhub_enabled` |
| A.5.3 | Segregation of Duties | ❌ 실패 | 0 / 1 | `iam_securityaudit_role_created` |
| A.5.6 | Contact With Special Interest Groups | ❌ 실패 | 0 / 1 | `account_maintain_different_contact_details_to_security_billing_and_operations` |
| A.5.13 | Labelling Of Information | ❌ 실패 | 0 / 1 | `organizations_tags_policies_enabled_and_attached` |
| A.5.15 | Access Control | ❌ 실패 | 18 / 2 | `iam_password_policy_expires_passwords_within_90_days_or_less`, `iam_role_access_not_stale_to_bedrock` |
| A.5.16 | Identity Management | ❌ 실패 | 0 / 1 | `config_recorder_all_regions_enabled` |
| A.5.17 | Authentication Information | ✅ 통과 | 2 / 0 | - |
| A.5.18 | Access Rights | ❌ 실패 | 19 / 1 | `iam_aws_attached_policy_no_administrative_privileges` |
| A.5.19 | Information Security In Supplier Relationships | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.5.21 | Managing Information Security In The ICT Supply Chain | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.5.22 | Monitor, Review And Change Management Of Supplier Services | ❌ 실패 | 0 / 1 | `config_recorder_all_regions_enabled` |
| A.5.25 | Assessment And Decision On Information Security Events | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.5.26 | Response To Information Security Incidents | ✅ 통과 | 3 / 0 | - |
| A.5.28 | Collection Of Evidence | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.5.29 | Information Security During Disruption | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.8.1 | User Endpoint Devices | ❌ 실패 | 10 / 2 | `ec2_instance_public_ip` |
| A.8.2 | Privileged Access Rights | ❌ 실패 | 23 / 1 | `iam_aws_attached_policy_no_administrative_privileges` |
| A.8.3 | Information Access Restriction | ❌ 실패 | 4 / 1 | `organizations_account_part_of_organizations` |
| A.8.5 | Secure Authentication | ❌ 실패 | 3 / 1 | `iam_user_hardware_mfa_enabled` |
| A.8.7 | Protection Against Malware | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.8.9 | Configuration Management | ❌ 실패 | 0 / 1 | `guardduty_is_enabled` |
| A.8.10 | Information Deletion | ❌ 실패 | 6 / 1 | `s3_bucket_lifecycle_enabled` |
| A.8.11 | Data Masking | ❌ 실패 | 7 / 7 | `cloudtrail_kms_encryption_enabled`, `cloudwatch_log_group_kms_encryption_enabled`, `kms_cmk_not_deleted_unintentionally`, `s3_bucket_kms_encryption` |
| A.8.13 | Information Backup | ❌ 실패 | 0 / 1 | `backup_vaults_exist` |
| A.8.14 | Redundancy of information processing facilities | ❌ 실패 | 0 / 6 | `ec2_ebs_volume_protected_by_backup_plan`, `s3_bucket_cross_region_replication`, `vpc_subnet_different_az` |
| A.8.15 | Logging | ❌ 실패 | 11 / 28 | `bedrock_model_invocation_logging_enabled`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_group_kms_encryption_enabled`, `cloudwatch_log_group_retention_policy_specific_days_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_log_metric_filter_aws_organizations_changes`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`, `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_unauthorized_api_calls`, `s3_bucket_server_access_logging_enabled` |
| A.8.16 | Monitoring Activities | ❌ 실패 | 10 / 25 | `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_group_kms_encryption_enabled`, `cloudwatch_log_group_retention_policy_specific_days_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_log_metric_filter_aws_organizations_changes`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`, `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_unauthorized_api_calls` |
| A.8.20 | Network Security | ❌ 실패 | 143 / 16 | `cloudwatch_changes_to_vpcs_alarm_configured`, `ec2_instance_internet_facing_with_instance_profile`, `ec2_instance_public_ip`, `ec2_instance_secrets_user_data`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `networkfirewall_in_all_vpc`, `vpc_different_regions`, `vpc_endpoint_for_ec2_enabled`, `vpc_subnet_different_az` |
| A.8.21 | Security of Network Services | ❌ 실패 | 143 / 16 | `cloudwatch_changes_to_vpcs_alarm_configured`, `ec2_instance_internet_facing_with_instance_profile`, `ec2_instance_public_ip`, `ec2_instance_secrets_user_data`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `networkfirewall_in_all_vpc`, `vpc_different_regions`, `vpc_endpoint_for_ec2_enabled`, `vpc_subnet_different_az` |
| A.8.22 | Segregation of Networks | ❌ 실패 | 143 / 16 | `cloudwatch_changes_to_vpcs_alarm_configured`, `ec2_instance_internet_facing_with_instance_profile`, `ec2_instance_public_ip`, `ec2_instance_secrets_user_data`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `networkfirewall_in_all_vpc`, `vpc_different_regions`, `vpc_endpoint_for_ec2_enabled`, `vpc_subnet_different_az` |
| A.8.23 | Web Filtering | ❌ 실패 | 1 / 1 | `securityhub_enabled` |
| A.8.24 | Use of Cryptography | ❌ 실패 | 7 / 7 | `cloudtrail_kms_encryption_enabled`, `cloudwatch_log_group_kms_encryption_enabled`, `kms_cmk_not_deleted_unintentionally`, `s3_bucket_kms_encryption` |

## 4. 실패한 점검 73개와 매핑

심각도 순. 「-」는 그 프레임워크에 매핑되지 않은 점검. 09-25에 수용한 항목(로그 보존, 고객 관리형 키, 단일 AZ 등)과 이유는 [`04-audit-prowler.md`](04-audit-prowler.md) 3절, 원인별 분류는 7절.

| 점검 | 설명 | 심각도 | 실패 / 전체 | ISMS-P | ISO 27001 |
|---|---|---|---|---|---|
| `iam_aws_attached_policy_no_administrative_privileges` | Attached AWS-managed IAM policy does not allow '*:*' administrative privileges | critical | 1 / 10 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | A.5.18, A.8.2 |
| `iam_root_hardware_mfa_enabled` | Root account has a hardware MFA device enabled | critical | 1 / 1 | 2.5.3, 2.5.5, 2.10.2 | - |
| `kms_cmk_not_deleted_unintentionally` | AWS KMS customer managed key is not scheduled for deletion | critical | 1 / 1 | 2.7.2, 2.9.2, 2.10.1 | A.8.11, A.8.24 |
| `cloudwatch_alarm_actions_alarm_state_configured` | CloudWatch metric alarm has actions configured for the ALARM state | high | 2 / 2 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | - |
| `ec2_ebs_volume_snapshots_exists` | EBS volume has at least one snapshot | high | 3 / 3 | 2.9.3, 2.12.1 | - |
| `ec2_instance_internet_facing_with_instance_profile` | EC2 instance is not internet-facing with an instance profile attached | high | 2 / 3 | 2.5.6, 2.6.1, 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_secrets_user_data` | EC2 instance user data contains no secrets | high | 1 / 3 | 2.7.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_networkacl_allow_ingress_any_port` | Network ACL does not allow ingress from 0.0.0.0/0 to any port | high | 2 / 2 | 2.6.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `guardduty_is_enabled` | GuardDuty detector is enabled and not suspended | high | 1 / 1 | 2.10.1, 2.10.2 | A.5.19, A.5.21, A.5.25, A.5.28, A.5.29, A.8.7, A.8.9 |
| `iam_role_administratoraccess_policy` | IAM role does not have AdministratorAccess policy attached | high | 1 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `iam_user_hardware_mfa_enabled` | IAM user has hardware MFA enabled | high | 1 / 1 | 2.5.3, 2.10.2 | A.8.5 |
| `organizations_scp_check_deny_regions` | AWS Organization restricts operations to only the configured AWS Regions with SCP policies | high | 1 / 1 | 2.10.2 | - |
| `secretsmanager_automatic_rotation_enabled` | Secrets Manager secret has rotation enabled | high | 1 / 1 | 2.7.2, 2.10.2 | - |
| `securityhub_enabled` | Security Hub is enabled with standards or integrations configured | high | 1 / 1 | 2.10.1, 2.10.2 | A.5.1, A.8.23 |
| `account_maintain_different_contact_details_to_security_billing_and_operations` | AWS account has distinct Security, Billing, and Operations contact details, different from each other and from the root contact | medium | 1 / 1 | 2.10.2 | A.5.6 |
| `bedrock_guardrails_configured` | Bedrock has at least one guardrail configured in the audited region | medium | 1 / 1 | 2.10.2 | - |
| `bedrock_model_invocation_logging_enabled` | Amazon Bedrock model invocation logging is enabled | medium | 1 / 1 | 2.9.4, 2.10.2 | A.8.15 |
| `cloudtrail_bucket_requires_mfa_delete` | CloudTrail trail S3 bucket has MFA delete enabled | medium | 1 / 1 | 2.5.3, 2.9.4, 2.10.1, 2.10.2 | - |
| `cloudtrail_kms_encryption_enabled` | CloudTrail trail logs are encrypted at rest with a KMS key | medium | 1 / 1 | 2.7.2, 2.10.1, 2.10.2 | A.8.11, A.8.15, A.8.16, A.8.24 |
| `cloudtrail_logs_s3_bucket_access_logging_enabled` | CloudTrail trail destination S3 bucket has access logging enabled | medium | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_changes_to_network_acls_alarm_configured` | CloudWatch log metric filter and alarm exist for Network ACL (NACL) change events | medium | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_changes_to_network_gateways_alarm_configured` | CloudWatch Logs metric filter and alarm exist for changes to network gateways | medium | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_changes_to_network_route_tables_alarm_configured` | Account monitors VPC route table changes with a CloudWatch Logs metric filter and alarm | medium | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | - |
| `cloudwatch_changes_to_vpcs_alarm_configured` | AWS account has a CloudWatch Logs metric filter and alarm for VPC changes | medium | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16, A.8.20, A.8.21, A.8.22 |
| `cloudwatch_log_group_kms_encryption_enabled` | CloudWatch log group is encrypted with an AWS KMS key | medium | 3 / 3 | 2.7.2, 2.10.1, 2.10.2 | A.8.11, A.8.15, A.8.16, A.8.24 |
| `cloudwatch_log_group_retention_policy_specific_days_enabled` | CloudWatch log group has a retention policy of at least the configured minimum days or never expires | medium | 3 / 3 | 2.9.4, 2.10.1, 2.10.2 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled` | CloudWatch Logs metric filter and alarm exist for AWS Config configuration changes | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled` | CloudWatch Logs metric filter and alarm exist for CloudTrail configuration changes | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_authentication_failures` | Account has a CloudWatch Logs metric filter and alarm for AWS Management Console authentication failures | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_aws_organizations_changes` | CloudWatch Logs metric filter and alarm exist for AWS Organizations changes | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk` | Account has a CloudWatch log metric filter and alarm for disabling or scheduled deletion of customer-managed KMS keys | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes` | CloudWatch log metric filter and alarm exist for S3 bucket policy changes | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_policy_changes` | CloudWatch Logs metric filter and alarm exist for IAM policy changes | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_root_usage` | Account has a CloudWatch Logs metric filter and alarm for root account usage | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_security_group_changes` | CloudWatch Logs metric filter and alarm exist for security group changes | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_sign_in_without_mfa` | CloudWatch log metric filter and alarm exist for Management Console sign-in without MFA | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudwatch_log_metric_filter_unauthorized_api_calls` | CloudWatch Logs metric filter and alarm exist for unauthorized API calls | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `config_recorder_all_regions_enabled` | AWS Config recorder is enabled and not in failure state or disabled | medium | 1 / 1 | 2.10.2, 2.11.3 | A.5.16, A.5.22 |
| `drs_job_exist` | Region has AWS Elastic Disaster Recovery (DRS) enabled with at least one recovery job | medium | 1 / 1 | 2.10.2, 2.12.1, 2.12.2 | - |
| `ec2_ebs_volume_protected_by_backup_plan` | EBS volume is protected by a backup plan | medium | 3 / 3 | 2.9.3, 2.12.1 | A.8.14 |
| `ec2_instance_public_ip` | EC2 instance does not have a public IP address | medium | 2 / 3 | 2.6.1, 2.10.2 | A.8.1, A.8.20, A.8.21, A.8.22 |
| `ec2_networkacl_allow_ingress_tcp_port_22` | Network ACL does not allow ingress from the Internet to TCP port 22 (SSH) | medium | 2 / 2 | 2.6.1, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_networkacl_allow_ingress_tcp_port_3389` | Network ACL does not allow ingress from the Internet to TCP port 3389 (RDP) | medium | 2 / 2 | 2.6.1, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `iam_password_policy_expires_passwords_within_90_days_or_less` | IAM account password policy enforces password expiration within 90 days or less | medium | 1 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_role_access_not_stale_to_bedrock` | Regular Bedrock access ensures IAM roles retain only actively used permissions | medium | 1 / 3 | - | A.5.15 |
| `inspector2_is_enabled` | Inspector2 is enabled for Amazon EC2 instances, ECR container images, Lambda functions, and Lambda code | medium | 1 / 1 | 2.10.1, 2.10.2, 2.11.2 | - |
| `macie_is_enabled` | Amazon Macie is enabled | medium | 1 / 1 | 2.10.1, 2.10.2 | - |
| `networkfirewall_in_all_vpc` | VPC has Network Firewall enabled | medium | 1 / 1 | 2.10.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `organizations_account_part_of_organizations` | AWS account is a member of an active AWS Organization | medium | 1 / 1 | 2.10.2 | A.8.3 |
| `organizations_opt_out_ai_services_policy` | AWS Organization has opted out of all AI services and child accounts cannot override the policy | medium | 1 / 1 | 2.10.2 | - |
| `s3_bucket_kms_encryption` | S3 bucket has server-side encryption with AWS KMS | medium | 2 / 2 | 2.7.2, 2.10.2 | A.8.11, A.8.24 |
| `s3_bucket_no_mfa_delete` | S3 bucket has MFA Delete enabled | medium | 2 / 2 | 2.5.3, 2.10.2 | - |
| `s3_bucket_server_access_logging_enabled` | S3 bucket has server access logging enabled | medium | 2 / 2 | 2.9.4, 2.10.2 | A.8.15 |
| `secretsmanager_secret_rotated_periodically` | AWS Secrets Manager secret is rotated within the configured maximum number of days | medium | 1 / 1 | 2.7.2, 2.10.2 | - |
| `ssmincidents_enabled_with_plans` | SSM Incidents replication set is ACTIVE and has at least one response plan | medium | 1 / 1 | 2.10.2, 2.11.1 | - |
| `vpc_different_regions` | VPCs are present in more than one region | medium | 1 / 1 | 2.9.2 | A.8.20, A.8.21, A.8.22 |
| `vpc_endpoint_for_ec2_enabled` | VPC has an Amazon EC2 VPC endpoint | medium | 1 / 1 | 2.6.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `vpc_subnet_different_az` | VPC has subnets in more than one Availability Zone | medium | 1 / 1 | 2.9.2 | A.8.14, A.8.20, A.8.21, A.8.22 |
| `backup_vaults_exist` | At least one AWS Backup vault exists | low | 1 / 1 | 2.9.3, 2.12.1 | A.8.13 |
| `bedrock_prompt_management_exists` | Amazon Bedrock Prompt Management prompts exist in the region | low | 1 / 1 | 2.10.2 | - |
| `cloudtrail_cloudwatch_logging_enabled` | CloudTrail trail has delivered logs to CloudWatch Logs in the last 24 hours | low | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudtrail_insights_exist` | CloudTrail trail has Insights enabled | low | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | - |
| `cloudtrail_s3_dataevents_read_enabled` | CloudTrail trail records S3 object-level read events for all S3 buckets | low | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `cloudtrail_s3_dataevents_write_enabled` | CloudTrail trail records all S3 object-level API operations for all buckets | low | 1 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `ec2_instance_detailed_monitoring_enabled` | EC2 instance has detailed monitoring enabled | low | 3 / 3 | 2.9.2 | - |
| `iam_check_saml_providers_sts` | IAM SAML provider exists in the account | low | 1 / 1 | 2.5.3, 2.10.2 | - |
| `iam_securityaudit_role_created` | At least one IAM role has the SecurityAudit AWS managed policy attached | low | 1 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | A.5.3 |
| `iam_support_role_created` | At least one IAM role has the AWSSupportAccess managed policy attached | low | 1 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2, 2.11.1 | - |
| `organizations_tags_policies_enabled_and_attached` | AWS Organization has tag policies enabled and attached | low | 1 / 1 | 2.1.3 | A.5.13 |
| `s3_bucket_cross_region_replication` | S3 bucket has cross-region replication configured to a bucket in a different region | low | 2 / 2 | 2.9.2 | A.8.14 |
| `s3_bucket_event_notifications_enabled` | S3 bucket has event notifications enabled | low | 2 / 2 | 2.10.2, 2.11.3 | - |
| `s3_bucket_lifecycle_enabled` | S3 bucket has a lifecycle configuration enabled | low | 1 / 2 | 2.9.3, 2.12.1 | A.8.10 |
| `s3_bucket_object_lock` | S3 bucket has Object Lock enabled | low | 1 / 2 | 2.9.3, 2.12.1 | - |

실패 점검 중 두 프레임워크 어디에도 매핑되지 않은 것: 0개

## 부록 A. 통과한 점검 108개와 매핑

| 점검 | 설명 | 심각도 | 실패 / 전체 | ISMS-P | ISO 27001 |
|---|---|---|---|---|---|
| `cloudtrail_logs_s3_bucket_is_not_publicly_accessible` | CloudTrail trail S3 bucket is not publicly accessible | critical | 0 / 1 | 2.6.1, 2.10.1 | A.8.1, A.8.15, A.8.16 |
| `ec2_instance_port_cassandra_exposed_to_internet` | EC2 instance does not have Cassandra ports (TCP 7000, 7001, 7199, 9042, 9160) open to the Internet | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_cifs_exposed_to_internet` | EC2 instance does not allow Internet ingress to TCP ports 139 or 445 (CIFS) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_elasticsearch_kibana_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to Elasticsearch and Kibana ports (TCP 9200, 9300, 5601) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.3, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_ftp_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP ports 20 or 21 (FTP) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_kafka_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 9092 (Kafka) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_kerberos_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP ports 88, 464, 749, or 750 (Kerberos) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_ldap_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP ports 389 or 636 (LDAP/LDAPS) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_memcached_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 11211 (Memcached) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_mongodb_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP ports 27017 or 27018 (MongoDB) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_mysql_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 3306 (MySQL) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_oracle_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP ports 1521, 2483, or 2484 (Oracle) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_postgresql_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 5432 (PostgreSQL) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_rdp_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 3389 (RDP) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_redis_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 6379 (Redis) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_sqlserver_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP ports 1433 or 1434 (SQL Server) | critical | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_ssh_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 22 (SSH) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_port_telnet_exposed_to_internet` | EC2 instance does not allow ingress from the Internet to TCP port 23 (Telnet) | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` | Security group does not have all ports open to the Internet | critical | 0 / 3 | 2.6.1, 2.6.2, 2.6.4, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `iam_inline_policy_no_administrative_privileges` | Inline IAM policy does not allow '*:*' administrative privileges | critical | 0 / 5 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | A.5.18, A.8.2 |
| `iam_no_root_access_key` | Root account has no active access keys | critical | 0 / 1 | 2.5.5, 2.7.2, 2.10.2 | A.5.15 |
| `iam_root_mfa_enabled` | Root account has MFA enabled | critical | 0 / 1 | 2.5.3, 2.5.5, 2.10.2 | A.5.15, A.5.17, A.8.5 |
| `iam_user_administrator_access_policy` | IAM user does not have AdministratorAccess policy attached | critical | 0 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `s3_bucket_policy_public_write_access` | S3 bucket policy does not allow public write access | critical | 0 / 2 | 2.5.6, 2.6.2, 2.10.2 | A.8.1 |
| `s3_bucket_public_access` | S3 bucket is not publicly accessible to Everyone or Authenticated Users | critical | 0 / 1 | 2.6.1, 2.6.2, 2.10.2 | A.8.1 |
| `s3_bucket_public_list_acl` | S3 bucket is not publicly listable by Everyone or any authenticated AWS user | critical | 0 / 1 | 2.5.6, 2.6.2, 2.10.2 | - |
| `s3_bucket_public_write_acl` | S3 bucket ACL does not grant write access to Everyone or any AWS customer | critical | 0 / 1 | 2.5.6, 2.6.2, 2.10.2 | - |
| `bedrock_full_access_policy_attached` | IAM role does not have AmazonBedrockFullAccess managed policy attached | high | 0 / 1 | 2.5.5 | A.8.2 |
| `cloudtrail_multi_region_enabled` | Region has at least one CloudTrail trail logging | high | 0 / 1 | 2.9.4, 2.10.1, 2.10.2 | - |
| `cloudwatch_alarm_actions_enabled` | CloudWatch metric alarm has actions enabled | high | 0 / 2 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | - |
| `cloudwatch_log_group_not_publicly_accessible` | CloudWatch Log Group is not publicly accessible | high | 0 / 3 | 2.6.1, 2.10.1, 2.10.2 | A.8.15, A.8.16 |
| `ec2_ebs_default_encryption` | EBS default encryption is enabled | high | 0 / 1 | 2.7.1, 2.10.2 | A.8.11, A.8.24 |
| `ec2_ebs_volume_encryption` | EBS volume is encrypted | high | 0 / 3 | 2.7.1, 2.10.2 | A.8.11, A.8.24 |
| `ec2_instance_account_imdsv2_enabled` | IMDSv2 is required by default for EC2 instances at the account level | high | 0 / 1 | 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_imdsv2_enabled` | EC2 instance requires IMDSv2 or has the instance metadata service disabled | high | 0 / 3 | 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port` | Security group has no 0.0.0.0/0 or ::/0 ingress to any port, or is attached only to allowed interface types or instance owners | high | 0 / 3 | 2.6.1, 2.6.2, 2.6.4, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to high-risk TCP ports | high | 0 / 3 | 2.6.1, 2.6.2, 2.6.4, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH) | high | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | Security group does not allow ingress from the Internet to TCP port 3389 (RDP) | high | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Cassandra TCP ports 7199, 9160, or 8888 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Elasticsearch/Kibana TCP ports 9200, 9300, and 5601 | high | 0 / 3 | 2.6.1, 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to FTP ports 20 or 21 | high | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 9092 (Kafka) | high | 0 / 3 | 2.6.1, 2.6.2, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Memcached TCP port 11211 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to MongoDB TCP ports 27017 and 27018 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to MySQL port 3306 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Oracle TCP ports 1521 or 2483 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Postgres TCP port 5432 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Redis TCP port 6379 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434` | Security group does not allow ingress from 0.0.0.0/0 or ::/0 to Microsoft SQL Server ports 1433 and 1434 | high | 0 / 3 | 2.6.1, 2.6.4, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23` | Security group does not allow ingress from the Internet to TCP port 23 (Telnet) | high | 0 / 3 | 2.6.1, 2.6.2, 2.6.6, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_allow_wide_open_public_ipv4` | Security group has no ingress or egress rules with public IPv4 CIDR ranges from /1 to /23 | high | 0 / 3 | 2.6.1, 2.10.2 | A.8.1, A.8.20, A.8.21, A.8.22 |
| `emr_cluster_account_public_block_enabled` | EMR account has Block Public Access enabled | high | 0 / 1 | 2.6.1, 2.10.2 | A.8.1 |
| `eventbridge_bus_cross_account_access` | AWS EventBridge event bus does not allow cross-account access | high | 0 / 1 | 2.5.6, 2.6.2, 2.10.2 | - |
| `eventbridge_bus_exposed` | AWS EventBridge event bus policy does not allow public access | high | 0 / 1 | 2.6.2, 2.10.2 | - |
| `iam_administrator_access_with_mfa` | IAM group members granted AdministratorAccess have MFA enabled | high | 0 / 1 | 2.5.3, 2.5.5, 2.10.2 | - |
| `iam_avoid_root_usage` | AWS account root user has not been used in the last day | high | 0 / 1 | 2.5.1, 2.5.5, 2.10.2 | A.5.15 |
| `iam_group_administrator_access_policy` | IAM group does not have AdministratorAccess policy attached | high | 0 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `iam_inline_policy_allows_privilege_escalation` | IAM inline policy does not allow privilege escalation | high | 0 / 5 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `iam_inline_policy_no_full_access_to_cloudtrail` | Inline IAM policy does not allow 'cloudtrail:*' privileges | high | 0 / 5 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `iam_role_cross_account_readonlyaccess_policy` | IAM role does not grant ReadOnlyAccess to external AWS accounts | high | 0 / 1 | 2.5.1, 2.5.6, 2.10.2 | - |
| `iam_role_cross_service_confused_deputy_prevention` | IAM service role prevents cross-service confused deputy attack | high | 0 / 4 | 2.5.1, 2.5.6, 2.10.2 | - |
| `iam_user_mfa_enabled_console_access` | IAM user has MFA enabled for console access or no console password is set | high | 0 / 1 | 2.5.3, 2.10.2 | A.5.15, A.5.17, A.8.5 |
| `iam_user_with_temporary_credentials` | IAM user does not use long-lived credentials to access services other than IAM or STS | high | 0 / 1 | 2.5.3, 2.10.2 | - |
| `s3_account_level_public_access_blocks` | S3 account-level Block Public Access ignores public ACLs and restricts public buckets | high | 0 / 1 | 2.6.1, 2.6.2, 2.10.2 | A.8.1 |
| `s3_bucket_cross_account_access` | S3 bucket policy does not allow cross-account access | high | 0 / 2 | 2.5.6, 2.6.2, 2.10.2 | - |
| `s3_bucket_level_public_access_block` | S3 bucket has Block Public Access with IgnorePublicAcls and RestrictPublicBuckets enabled at bucket or account level | high | 0 / 2 | 2.6.1, 2.6.2, 2.10.2 | - |
| `vpc_subnet_no_public_ip_by_default` | VPC subnet does not assign public IP addresses by default | high | 0 / 4 | 2.6.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `cloudtrail_bedrock_logging_enabled` | CloudTrail logs Amazon Bedrock API calls for security auditing | medium | 0 / 1 | - | A.8.15 |
| `cloudtrail_log_file_validation_enabled` | CloudTrail trail has log file validation enabled | medium | 0 / 1 | 2.9.4, 2.10.1, 2.10.2 | A.8.15, A.8.16 |
| `cloudwatch_cross_account_sharing_disabled` | CloudWatch does not allow cross-account sharing | medium | 0 / 1 | 2.6.2, 2.10.1, 2.10.2 | - |
| `cloudwatch_log_group_no_secrets_in_logs` | CloudWatch log group contains no secrets in its log events | medium | 0 / 3 | 2.9.4, 2.10.1, 2.10.2 | A.8.15, A.8.16 |
| `ec2_instance_managed_by_ssm` | EC2 instance is managed by AWS Systems Manager or not running | medium | 0 / 3 | 2.6.2, 2.10.2 | A.5.26 |
| `ec2_instance_older_than_specific_days` | EC2 instance is not older than the configured maximum age or is not running | medium | 0 / 3 | 2.9.2 | A.8.10 |
| `ec2_instance_paravirtual_type` | EC2 instance virtualization type is HVM | medium | 0 / 3 | 2.9.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_profile_attached` | EC2 instance is associated with an IAM instance profile role | medium | 0 / 3 | 2.5.1, 2.5.6, 2.10.2 | A.8.2, A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_from_launch_wizard` | Security group not created using the EC2 Launch Wizard | medium | 0 / 5 | 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_with_many_ingress_egress_rules` | Security group has 50 or fewer inbound rules and 50 or fewer outbound rules | medium | 0 / 5 | 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `iam_inline_policy_no_full_access_to_kms` | Inline IAM policy does not allow kms:* privileges | medium | 0 / 5 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `iam_inline_policy_no_wildcard_marketplace_subscribe` | Inline IAM policy does not allow 'aws-marketplace:Subscribe' on all resources | medium | 0 / 5 | 2.5.5 | A.5.18, A.8.2 |
| `iam_password_policy_minimum_length_14` | IAM password policy requires passwords to be at least 14 characters long | medium | 0 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_password_policy_number` | IAM password policy requires at least one number | medium | 0 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_password_policy_reuse_24` | IAM password policy prevents reuse of the last 24 passwords | medium | 0 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_password_policy_symbol` | IAM password policy requires at least one symbol | medium | 0 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_password_policy_uppercase` | IAM password policy requires at least one uppercase letter | medium | 0 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_policy_cloudshell_admin_not_attached` | No IAM users, groups, or roles have the AWSCloudShellFullAccess policy attached | medium | 0 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | - |
| `iam_rotate_access_key_90_days` | IAM user does not have active access keys older than 90 days | medium | 0 / 2 | 2.7.2, 2.10.2 | A.5.15 |
| `iam_user_accesskey_unused` | IAM user does not have unused access keys older than 45 days | medium | 0 / 2 | 2.7.2, 2.10.2 | A.5.15 |
| `iam_user_console_access_unused` | IAM user console access is disabled, used within the configured inactivity period, or never used | medium | 0 / 1 | 2.5.3, 2.10.2 | A.5.15 |
| `iam_user_no_setup_initial_access_key` | IAM user does not have active access keys that have never been used | medium | 0 / 2 | 2.7.2, 2.10.2 | - |
| `iam_user_two_active_access_key` | IAM user has at most one active access key | medium | 0 / 2 | 2.7.2, 2.10.2 | - |
| `s3_bucket_acl_prohibited` | S3 bucket has bucket ACLs disabled | medium | 0 / 2 | 2.6.2, 2.10.2 | - |
| `s3_bucket_default_encryption` | [DEPRECATED] S3 bucket has default server-side encryption (SSE) enabled | medium | 0 / 2 | 2.7.1, 2.10.2 | A.8.11, A.8.24 |
| `s3_bucket_object_versioning` | S3 bucket has object versioning enabled | medium | 0 / 2 | 2.9.3, 2.12.1 | A.8.3, A.8.10 |
| `s3_bucket_secure_transport_policy` | S3 bucket policy denies requests over insecure transport | medium | 0 / 2 | 2.7.1, 2.10.2 | - |
| `secretsmanager_secret_unused` | Secrets Manager secret has been accessed within the last 90 days | medium | 0 / 1 | 2.7.2, 2.10.2 | - |
| `vpc_flow_logs_enabled` | VPC flow logs are enabled | medium | 0 / 1 | 2.9.4, 2.10.2 | A.8.15, A.8.16, A.8.20, A.8.21, A.8.22, A.8.23 |
| `vpc_subnet_separate_private_public` | VPC has both public and private subnets | medium | 0 / 1 | 2.6.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `accessanalyzer_enabled` | IAM Access Analyzer is enabled | low | 0 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | A.8.3 |
| `accessanalyzer_enabled_without_findings` | IAM Access Analyzer analyzer is active and has no active findings | low | 0 / 1 | 2.5.1, 2.5.5, 2.5.6, 2.10.2 | A.8.3 |
| `cloudtrail_multi_region_enabled_logging_management_events` | CloudTrail trail logs management events for read and write operations | low | 0 / 1 | 2.9.4, 2.10.1, 2.10.2, 2.11.3 | A.8.15, A.8.16 |
| `ec2_elastic_ip_unassigned` | Elastic IP is associated with an instance or network interface | low | 0 / 2 | 2.9.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_instance_uses_single_eni` | EC2 instance has no more than one Elastic Network Interface (ENI) attached | low | 0 / 3 | 2.6.1, 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `ec2_securitygroup_not_used` | Non-default EC2 security group is in use | low | 0 / 3 | 2.10.2 | A.8.20, A.8.21, A.8.22 |
| `iam_password_policy_lowercase` | IAM password policy requires at least one lowercase letter | low | 0 / 1 | 2.5.4, 2.10.2 | A.5.15 |
| `iam_policy_attached_only_to_group_or_roles` | IAM user has no inline or attached policies | low | 0 / 1 | 2.5.1, 2.5.6, 2.10.2 | A.5.15 |
| `kms_cmk_are_used` | KMS customer managed key is enabled or scheduled for deletion | low | 0 / 1 | 2.7.2, 2.10.1, 2.10.2 | A.8.5, A.8.11, A.8.24 |
| `resourceexplorer2_indexes_found` | Resource Explorer indexes exist | low | 0 / 1 | 2.9.2 | - |

## 부록 B. 수동 점검 6개

| 점검 | 설명 | 심각도 | 실패 / 전체 | ISMS-P | ISO 27001 |
|---|---|---|---|---|---|
| `kms_key_enclave_debug_attestation_detected` | No Nitro Enclave debug-mode attestation observed against this KMS key | high | 0 / 1 | - | A.8.16 |
| `account_maintain_current_contact_details` | AWS account contact information is current | medium | 0 / 1 | 2.10.2 | A.5.5 |
| `account_security_contact_information_is_registered` | AWS account has security alternate contact registered | medium | 0 / 1 | 2.10.2 | A.5.5 |
| `account_security_questions_are_registered_in_the_aws_account` | [DEPRECATED] AWS root user has security challenge questions configured | medium | 0 / 1 | 2.5.1, 2.5.3, 2.10.2 | - |
| `kms_key_enclave_attestation_unknown_image` | No enclave with an unknown image identity has called this KMS key | medium | 0 / 1 | - | A.8.16 |
| `trustedadvisor_errors_and_warnings` | Trusted Advisor check has no errors or warnings | medium | 0 / 1 | 2.10.1, 2.10.2, 2.11.3 | - |
