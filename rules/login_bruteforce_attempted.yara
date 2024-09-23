rule login_bruteforce_attempted
{
  meta:
     subject = "login bruteforce attempted"
     description = "It identifies patterns of repeated login failures originating from the same IP to more than 10 users over a one-hour time period. Adversaries often collect valid user accounts and initiate brute force attacks in an attempt to gain unauthorized access to a target account."
     tactic = "Credential Access"
     technique = "Brute Force"
     subtechnique = "T1110.001, T1110.003, T1110.004"
     tool = ""
     datasource = "User Account"
     category = ""
     product = ""
     logsource = "Access Point, EDR, Firewall, NGFW, Iaas, Network Security Monitor(NSM), SSO, Switch, Web Server, Virtulization, WLANController, Email Gateway"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Low"
     severity = "Low"
     falsePositives = "Signals may generate if multiple users failed to login into external portals like azure AD within short time intervals. Whitelist your outbound internet NAT gateway IPs to avoid such benign detections."
     externalSubject = "0"
     externalMITRE = "0"
     version = "7"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
    $e.target.user.userid = $user
    $e.target.user.userid != ""
    $e.target.user.userid != /.*?\$$/
    $e.target.user.userid != "Not Available"
    $e.extensions.auth.mechanism != "OTP" and $e.target.user.user_authentication_status != "SUSPENDED" and $e.target.user.user_authentication_status != "NO_ACTIVE_CREDENTIALS"
    not $e.security_result.description in %whitelisted_login_failure_reason_codes //This is to eliminate noise cases like user login attempt with expired login credentials, user is presented MFA, username does not exist.
    not $e.principal.ip in %internet_NAT_gateway_IPs
    not $e.principal.ip in %vulnerability_scanners
    not $e.principal.ip in %loopback_ip_addresses

  match:
    $ip over 1h

  condition:
    #user >= 10
}
