rule threat_feed_IP_match_detected_outbound
{
  meta:
     subject = "threat feed IP match detected outbound"
     description = "This rule identifies any communication from an internal host to IP addresses that have been marked as suspicous by threat intelligence source. These blacklisted IP addresses are known to be associated with malicious activity, such as hosting malware, phishing scams, or command and control servers for botnets. Engaging with these blacklisted IPs can indicates system compromise, and other security risks."
     tactic = "Command and Control"
     technique = "Application Layer Protocol"
     subtechnique = ""
     tool = ""
     datasource = "Network Traffic"
     category = ""
     product = ""
     logsource = "NGFW, Firewall, Web proxy, Netflow, Network Security Monitor(NSM)"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Medium"
     severity = "Medium"
     falsePositives = "It could be benign when threat intelligence source misclassifies threat association with IP address"
     externalSubject = "0"
     externalMITRE = "0"
     version = "5"

  events:
        //($e1.metadata.event_type = "NETWORK_HTTP" or $e1.metadata.event_type = "NETWORK_CONNECTION") and 
        $e1.target.ip != ""
        $e1.target.ip_geo_artifact.location.country_or_region != ""
        $e1.target.ip = $target_ip //Capturing destination IP from event to correlate with Threat Intelligence feeds
        //$e1.security_result.action = "ALLOW" //Looking for events which are allowed at security device
       
        $e2.graph.metadata.vendor_name = "RECORDED_FUTURE_IOC" nocase $e2.graph.metadata.vendor_name = "" nocase
        $e2.graph.metadata.entity_type = "IP_ADDRESS"
        $e2.graph.entity.ip = $target_ip
        $e2.graph.metadata.threat.category_details != ""
 
  match:
      $target_ip over 5m

  condition:
    $e1 and $e2
}
