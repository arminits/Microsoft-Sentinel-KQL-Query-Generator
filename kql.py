from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoServiceError

def generate_kql_query(event_id=None, url=None, start_time=None, end_time=None, source_ip=None, destination_ip=None, event_type=None, username=None, logon_type=None, severity=None, event_description=None, event_category=None, email_address=None, sender_mail_from_address=None, sender_from_address=None, sender_display_name=None, recipient_email_address=None, subject=None, threat_types=None, attachment_count=None, url_count=None, audit_event_type=None, user_principal_name=None, client_ip=None, category=None, result_status=None, operation=None, device_id=None, device_name=None, file_name=None, folder_path=None, sha1=None, sha256=None, md5=None, file_origin_url=None, file_origin_referrer_url=None, file_origin_ip=None, previous_folder_path=None, previous_file_name=None, file_size=None, initiating_process_account_name=None, initiating_process_account_sid=None, initiating_process_md5=None, initiating_process_sha1=None, initiating_process_sha256=None, initiating_process_folder_path=None, initiating_process_file_name=None, initiating_process_file_size=None, initiating_process_id=None, initiating_process_command_line=None):
    if not event_category:
        event_category = "Security"

    event_category = event_category.lower()
    event_table_map = {
        "security": "SecurityEvent",
        "email": "EmailEvents",
        "audit": "AuditEvents",
        "devicefile": "DeviceFileEvents",
        # Add more event categories and corresponding tables here as needed
        # For example:
        # "login": "LoginEvents",
        # "logout": "LogoutEvents",
        # "file": "FileEvents",
        # "database": "DatabaseEvents",
    }

    query = event_table_map.get(event_category, event_table_map["security"])

    conditions = []

    if event_category == "security":
        if event_id:
            conditions.append(f"EventID == {event_id}")

        if url:
            conditions.append(f"Url == '{url}'")

        if start_time and end_time:
            conditions.append(f"timestamp between(datetime({start_time}) .. datetime({end_time}))")

        if source_ip:
            conditions.append(f"SourceIP == '{source_ip}'")

        if destination_ip:
            conditions.append(f"DestinationIP == '{destination_ip}'")

        if event_type:
            conditions.append(f"EventType == '{event_type}'")

        if username:
            conditions.append(f"Account == '{username}'")

        if logon_type:
            conditions.append(f"LogonType == '{logon_type}'")

        if severity:
            conditions.append(f"Severity == '{severity}'")

        if event_description:
            conditions.append(f"Description has '{event_description}'")

    elif event_category == "email":
        query = "EmailEvents"
        if email_address:
            conditions.append(f"EmailAddress == '{email_address}'")

        if start_time and end_time:
            conditions.append(f"timestamp between(datetime({start_time}) .. datetime({end_time}))")

        if event_id:
            conditions.append(f"EventID == {event_id}")

        if url:
            conditions.append(f"Url == '{url}'")

        if source_ip:
            conditions.append(f"SourceIP == '{source_ip}'")

        if destination_ip:
            conditions.append(f"DestinationIP == '{destination_ip}'")

        if event_type:
            conditions.append(f"EventType == '{event_type}'")

        if username:
            conditions.append(f"Account == '{username}'")

        if logon_type:
            conditions.append(f"LogonType == '{logon_type}'")

        if severity:
            conditions.append(f"Severity == '{severity}'")

        if event_description:
            conditions.append(f"Description has '{event_description}'")

        if sender_mail_from_address:
            conditions.append(f"SenderMailFromAddress == '{sender_mail_from_address}'")

        if sender_from_address:
            conditions.append(f"SenderFromAddress == '{sender_from_address}'")

        if sender_display_name:
            conditions.append(f"SenderDisplayName == '{sender_display_name}'")

        if recipient_email_address:
            conditions.append(f"RecipientEmailAddress == '{recipient_email_address}'")

        if subject:
            conditions.append(f"Subject == '{subject}'")

        if threat_types:
            conditions.append(f"ThreatTypes == '{threat_types}'")

        if attachment_count:
            conditions.append(f"AttachmentCount == '{attachment_count}'")

        if url_count:
            conditions.append(f"UrlCount == '{url_count}'")

    elif event_category == "audit":
        query = "AuditEvents"
        if audit_event_type:
            conditions.append(f"AuditEventType == '{audit_event_type}'")

        if start_time and end_time:
            conditions.append(f"timestamp between(datetime({start_time}) .. datetime({end_time}))")

        # Additional fields for AuditEvents
        if user_principal_name:
            conditions.append(f"UserPrincipalName == '{user_principal_name}'")

        if client_ip:
            conditions.append(f"ClientIP == '{client_ip}'")

        if category:
            conditions.append(f"Category == '{category}'")

        if result_status:
            conditions.append(f"ResultStatus == '{result_status}'")

        if operation:
            conditions.append(f"Operation == '{operation}'")

    elif event_category == "devicefile":
        query = "DeviceFileEvents"
        if device_id:
            conditions.append(f"DeviceId == '{device_id}'")

        if device_name:
            conditions.append(f"DeviceName == '{device_name}'")

        if file_name:
            conditions.append(f"FileName == '{file_name}'")

        if folder_path:
            conditions.append(f"FolderPath == '{folder_path}'")

        if sha1:
            conditions.append(f"SHA1 == '{sha1}'")

        if sha256:
            conditions.append(f"SHA256 == '{sha256}'")

        if md5:
            conditions.append(f"MD5 == '{md5}'")

        if file_origin_url:
            conditions.append(f"FileOriginUrl == '{file_origin_url}'")

        if file_origin_referrer_url:
            conditions.append(f"FileOriginReferrerUrl == '{file_origin_referrer_url}'")

        if file_origin_ip:
            conditions.append(f"FileOriginIP == '{file_origin_ip}'")

        if previous_folder_path:
            conditions.append(f"PreviousFolderPath == '{previous_folder_path}'")

        if previous_file_name:
            conditions.append(f"PreviousFileName == '{previous_file_name}'")

        if file_size:
            conditions.append(f"FileSize == '{file_size}'")

        if initiating_process_account_name:
            conditions.append(f"InitiatingProcessAccountName == '{initiating_process_account_name}'")

        if initiating_process_account_sid:
            conditions.append(f"InitiatingProcessAccountSid == '{initiating_process_account_sid}'")

        if initiating_process_md5:
            conditions.append(f"InitiatingProcessMD5 == '{initiating_process_md5}'")

        if initiating_process_sha1:
            conditions.append(f"InitiatingProcessSHA1 == '{initiating_process_sha1}'")

        if initiating_process_sha256:
            conditions.append(f"InitiatingProcessSHA256 == '{initiating_process_sha256}'")

        if initiating_process_folder_path:
            conditions.append(f"InitiatingProcessFolderPath == '{initiating_process_folder_path}'")

        if initiating_process_file_name:
            conditions.append(f"InitiatingProcessFileName == '{initiating_process_file_name}'")

        if initiating_process_file_size:
            conditions.append(f"InitiatingProcessFileSize == '{initiating_process_file_size}'")

        if initiating_process_id:
            conditions.append(f"InitiatingProcessId == '{initiating_process_id}'")

        if initiating_process_command_line:
            conditions.append(f"InitiatingProcessCommandLine == '{initiating_process_command_line}'")

    if conditions:
        query += " | where " + " and ".join(conditions)

    return query

def main():
    print("Welcome to the Microsoft Sentinel KQL Query Generator!")
    event_category = input("Enter Event Category (Options: Security, Email, Audit, DeviceFile): ")

    # Prompt only relevant questions based on the selected event category
    if event_category.lower() == "email":
        email_address = input("Enter Email Address (optional): ")
        sender_mail_from_address = input("Enter Sender Mail From Address (optional): ")
        sender_from_address = input("Enter Sender From Address (optional): ")
        sender_display_name = input("Enter Sender Display Name (optional): ")
        recipient_email_address = input("Enter Recipient Email Address (optional): ")
        subject = input("Enter Subject (optional): ")
        threat_types = input("Enter Threat Types (optional): ")
        attachment_count = input("Enter Attachment Count (optional): ")
        url_count = input("Enter URL Count (optional): ")

        kql_query = generate_kql_query(
            event_category=event_category,
            email_address=email_address,
            sender_mail_from_address=sender_mail_from_address,
            sender_from_address=sender_from_address,
            sender_display_name=sender_display_name,
            recipient_email_address=recipient_email_address,
            subject=subject,
            threat_types=threat_types,
            attachment_count=attachment_count,
            url_count=url_count
        )
    elif event_category.lower() == "audit":
        audit_event_type = input("Enter Audit Event Type (optional): ")
        user_principal_name = input("Enter User Principal Name (optional): ")
        client_ip = input("Enter Client IP (optional): ")
        category = input("Enter Category (optional): ")
        result_status = input("Enter Result Status (optional): ")
        operation = input("Enter Operation (optional): ")

        kql_query = generate_kql_query(
            event_category=event_category,
            audit_event_type=audit_event_type,
            user_principal_name=user_principal_name,
            client_ip=client_ip,
            category=category,
            result_status=result_status,
            operation=operation
        )
    elif event_category.lower() == "devicefile":
        device_id = input("Enter Device ID (optional): ")
        device_name = input("Enter Device Name (optional): ")
        file_name = input("Enter File Name (optional): ")
        folder_path = input("Enter Folder Path (optional): ")
        sha1 = input("Enter SHA1 (optional): ")
        sha256 = input("Enter SHA256 (optional): ")
        md5 = input("Enter MD5 (optional): ")
        file_origin_url = input("Enter File Origin URL (optional): ")
        file_origin_referrer_url = input("Enter File Origin Referrer URL (optional): ")
        file_origin_ip = input("Enter File Origin IP (optional): ")
        previous_folder_path = input("Enter Previous Folder Path (optional): ")
        previous_file_name = input("Enter Previous File Name (optional): ")
        file_size = input("Enter File Size (optional): ")
        initiating_process_account_name = input("Enter Initiating Process Account Name (optional): ")
        initiating_process_account_sid = input("Enter Initiating Process Account SID (optional): ")
        initiating_process_md5 = input("Enter Initiating Process MD5 (optional): ")
        initiating_process_sha1 = input("Enter Initiating Process SHA1 (optional): ")
        initiating_process_sha256 = input("Enter Initiating Process SHA256 (optional): ")
        initiating_process_folder_path = input("Enter Initiating Process Folder Path (optional): ")
        initiating_process_file_name = input("Enter Initiating Process File Name (optional): ")
        initiating_process_file_size = input("Enter Initiating Process File Size (optional): ")
        initiating_process_id = input("Enter Initiating Process ID (optional): ")
        initiating_process_command_line = input("Enter Initiating Process Command Line (optional): ")

        kql_query = generate_kql_query(
            event_category=event_category,
            device_id=device_id,
            device_name=device_name,
            file_name=file_name,
            folder_path=folder_path,
            sha1=sha1,
            sha256=sha256,
            md5=md5,
            file_origin_url=file_origin_url,
            file_origin_referrer_url=file_origin_referrer_url,
            file_origin_ip=file_origin_ip,
            previous_folder_path=previous_folder_path,
            previous_file_name=previous_file_name,
            file_size=file_size,
            initiating_process_account_name=initiating_process_account_name,
            initiating_process_account_sid=initiating_process_account_sid,
            initiating_process_md5=initiating_process_md5,
            initiating_process_sha1=initiating_process_sha1,
            initiating_process_sha256=initiating_process_sha256,
            initiating_process_folder_path=initiating_process_folder_path,
            initiating_process_file_name=initiating_process_file_name,
            initiating_process_file_size=initiating_process_file_size,
            initiating_process_id=initiating_process_id,
            initiating_process_command_line=initiating_process_command_line
        )
    else:
        event_id = input("Enter Event ID (optional): ")
        url = input("Enter URL (optional): ")
        start_time = input("Enter Start Time (optional): ")
        end_time = input("Enter End Time (optional): ")
        source_ip = input("Enter Source IP (optional): ")
        destination_ip = input("Enter Destination IP (optional): ")
        event_type = input("Enter Event Type (optional): ")
        username = input("Enter Username (optional): ")
        logon_type = input("Enter Logon Type (optional): ")
        severity = input("Enter Severity (optional): ")
        event_description = input("Enter Event Description Keyword (optional): ")
        
        kql_query = generate_kql_query(
            event_category=event_category,
            event_id=event_id,
            url=url,
            start_time=start_time,
            end_time=end_time,
            source_ip=source_ip,
            destination_ip=destination_ip,
            event_type=event_type,
            username=username,
            logon_type=logon_type,
            severity=severity,
            event_description=event_description
        )

#add your cluster here
    #kusto_cluster = "https://<cluster-name>.<region>.kusto.windows.net"
    #kusto_database = "<database-name>"
    #kusto_client = KustoClient(KustoConnectionStringBuilder.with_aad_device_authentication(kusto_cluster))
    #response = kusto_client.execute_query(kusto_database, kql_query)
    
    print("\nGenerated KQL Query:")
    print(kql_query)

    #print("\nQuery Result:")
    #for row in response.primary_results[0]:
        #print(row)

if __name__ == "__main__":
    main()
