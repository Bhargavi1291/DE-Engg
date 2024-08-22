rule tor_exit_nodes_connections_detected
{
  meta:
     subject = "tor exit nodes connections detected"
     description = "Adversaries may use a connection proxy to direct network traffic between systems or act as an // intermediary for network communications to a command and control server to avoid direct connections to their // infrastructure. // This detection looks for connections to / from TOR exit nodes."
     tactic = "Command and Control"
     technique = "Proxy"
     subtechnique = "Multi-hop Proxy"
     tool = ""
     datasource = "Network Traffic"
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
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e1.graph.metadata.entity_type = "IP_ADDRESS"
    $e1.graph.metadata.threat.threat_feed_name != ""
    $e1.graph.metadata.threat.threat_feed_name != "Tor Exit Nodes"
   
match:
	$ip over 3h
condition:
	$e and $e1
}
