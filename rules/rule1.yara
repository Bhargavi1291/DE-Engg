rule okta_verify_mfa_bruteforce_with_success
{
  meta:
     subject = "okta verify mfa bruteforce with success"
     description = "None"
     tactic = "Initial Access"
     technique = ""
     subtechnique = ""
     tool = ""
     datasource = ""
     category = ""
     product = ""
     logsource = ""
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "High"
     severity = "High"
     falsePositives = ""
     externalSubject = "0"
     externalMITRE = "0"
     version = "1"

  events:
    $e.metadata.log_type = "OKTA"
    $e.metadata.product_event_type = "system.push.send_factor_verify_push"
    $user = $e.principal.user.userid
    $product_log_id = $e.metadata.product_log_id
    $e.network.parent_session_id = $parent_session_id

    $e2.metadata.log_type = "OKTA"
    $e2.metadata.event_type = "USER_LOGIN"
    $e2.metadata.product_event_type = "user.authentication.auth_via_mfa"
    $e2.network.parent_session_id = $parent_session_id    
    $e2.target.user.userid = $user

    $e.metadata.event_timestamp.seconds <= $e2.metadata.event_timestamp.seconds
 
  match:
    $user over 5m

  outcome:
    $offending_user = array_distinct($user)
    $mfa_attempts = count_distinct($e.metadata.product_log_id)
    $ips_involved = array_distinct($e.principal.ip)
    $involved_locations = array_distinct($e.principal.ip_geo_artifact.location.country_or_region)

  condition:
    #product_log_id > 6 and $e2
}
