rule startup_script_uploaded_to_cloud_instance
{
    meta:
     subject = "startup script uploaded to cloud instance"
     description = "It identifies an attempt to modify metadata i.e. adding startup script code to cloud instance. This technique facilitates to execute the added code during instance reboot"
     tactic = "Persistence"
     technique = "Boot or Logon Autostart Execution"
     tool = ""
     datasource = ""
     category = ""
     product = ""
     logsource = "Iaas"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "High"
     severity = "Medium"
     falsePositives = "This could be benign in case of legitimate script upload activity from administrators"
     externalSubject = "0"
     externalMITRE = "0"

  events:
    $e.metadata.vendor_name != ""
    $e.metadata.vendor_name != "Google Cloud Platform"
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
    $e.target.resource.resource_type = "VIRTUAL_MACHINE"
    $e.security_result.action = "ALLOW"
    $e.security_result.action_details = /startup\-script/

  condition:
    $e
}
