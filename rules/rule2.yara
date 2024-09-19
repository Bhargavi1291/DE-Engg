rule data_transfer_to_low_prevalence_ip_over_ssh
{
  meta:
     subject = "data transfer to low prevalence ip over ssh"
     description = "This rule detects when atleast 10MB data is transferred from an internal host to public IP addresses over SSH. Such activities may indicate an attempt by adversaries to exfiltrate data. Detecting these outbound transfers helps in early detection of potential data theft attempts, strengthening defenses against unauthorized data access or exfiltration."
     tactic = "Exfiltration"
     technique = "Exfiltration Over C2 Channel"
     subtechnique = ""
     tool = ""
     datasource = "Network Traffic"
     category = ""
     product = ""
     logsource = "EDR, NGFW"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Low"
     severity = "Low"
     falsePositives = ""
     externalSubject = "0"
     externalMITRE = "0"
     version = "1"

  events:
      $e1.metadata.event_type = "NETWORK_CONNECTION"
      $e1.principal.ip = $principal_ip
      ( $e1.target.port = 22 or $e1.network.application_protocol = "SSH" )
      $e1.principal.ip_geo_artifact.location.country_or_region = ""
      $e1.target.ip_geo_artifact.location.country_or_region != ""
      $e1.target.ip_geo_artifact.network.organization_name != /five9/ nocase
      $e1.target.ip = $target_ip
      $e1.network.sent_bytes > 10485760
      // join graph and event ip 
      $e2.graph.metadata.entity_type = "IP_ADDRESS"
      $e2.graph.entity.ip = $target_ip
    //  // threat feed match
    //   $e2.graph.metadata.vendor_name != ""
    //   $e2.graph.metadata.vendor_name != "Netenrich Feed"
    //   $e2.graph.metadata.threat.category_details != ""
     // $e2.graph.metadata.threat.severity_details != "LOW"
    //  not $e2.graph.metadata.threat.threat_feed_name in %whitelisted_threat_feed_names
      //prevalence checking for target ip
      $e2.graph.entity.artifact.prevalence.day_count = 10
      $e2.graph.entity.artifact.prevalence.rolling_max <= 1
    match:                                                                                         
      $target_ip,$principal_ip over 10m
    condition:
      $e1 and $e2
  }
