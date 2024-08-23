rule ipfs_gateway_detected
{
  meta:
     subject = "ipfs gateway detected"
     description = "IPFS HTTPS Gateway detected. IPFS is often used for phishing attacks: https://www.netcraft.com/blog/disrupting-ipfs-phishing-attacks/"
     tactic = "Initial Access"
     technique = "Phishing"
     subtechnique = ""
     tool = ""
     datasource = "Network Traffic, Application Log"
     category = ""
     product = "Zscaler"
     logsource = "Web proxy"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Medium"
     severity = "Medium"
     falsePositives = ""
     externalSubject = "0"
     externalMITRE = "0"
     version = "1"

  events:
    $e.metadata.log_type = "ZSCALER_WEBPROXY"
    $e.metadata.product_name = "Zscaler Web Proxy"
    $e.metadata.vendor_name != ""
    $e.metadata.vendor_name != "Zscaler"
    $e.target.url in %ipfs_domains 
    $e.principal.user.userid = $user

  match:
    $user over 10m

  outcome:
    $bad_user = array_distinct($user)
    $ipfs_urls = array_distinct($e.target.url)
   
   //BAD SYNTAX BELOW
   // $description = "User $1 visited the following IPFS gateways or urls: $2"


  condition:
    #e > 0
}
