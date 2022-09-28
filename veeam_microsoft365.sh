#!/bin/bash
##      .SYNOPSIS
##      Grafana Dashboard for Veeam Backup for Microsoft 365 v6.0 - Using RestAPI to InfluxDB Script
## 
##      .DESCRIPTION
##      This Script will query the Veeam Backup for Microsoft 365 RestAPI and send the data directly to InfluxDB, which can be used to present it to Grafana. 
##      The Script and the Grafana Dashboard it is provided as it is, and bear in mind you can not open support Tickets regarding this project. It is a Community Project
##	
##      .Notes
##      NAME:  veeam_microsoft365.sh
##      ORIGINAL veeam_microsoft365.sh
##      LASTEDIT: 11/03/2022
##      VERSION: 6.0
##      KEYWORDS: Veeam, InfluxDB, Grafana
   
##      .Link
##      https://jorgedelacruz.es/
##      https://jorgedelacruz.uk/

# Enable debugging with "true"
debug=true

##
# Configurations
##
# Endpoint URL for InfluxDB
veeamInfluxDBURL="http://YOURINFLUXSERVERIP" #Your InfluxDB Server, http://FQDN or https://FQDN if using SSL
veeamInfluxDBPort="8086" #Default Port
veeamInfluxDBBucket="veeam" # InfluxDB bucket name (not ID)
veeamInfluxDBToken="TOKEN" # InfluxDB access token with read/write privileges for the bucket
veeamInfluxDBOrg="ORG NAME" # InfluxDB organisation name (not ID)

veeamInfluxPostURL="$veeamInfluxDBURL:$veeamInfluxDBPort/api/v2/write?org=$veeamInfluxDBOrg&bucket=$veeamInfluxDBBucket&precision=s" # curl XPOST connection
veeamInfludPostAuth="Authorization: Token $veeamInfluxDBToken" # curl XPOST Authentication

if $debug; then echo "veeamInfluxPost: $veeamInfluxPost"; echo ""; fi

# Endpoint URL for login action
veeamUsername="YOURVBOUSER"
veeamPassword="YOURVBOPASSWORD"
veeamRestServer="https://YOURVBOSERVERIP"
veeamRestPort="4443" #Default Port
veeamBearer=$(curl -X POST --header "Content-Type: application/x-www-form-urlencoded" --header "Accept: application/json" -d "grant_type=password&username=$veeamUsername&password=$veeamPassword&refresh_token=%27%27" "$veeamRestServer:$veeamRestPort/v6/token" -k --silent | jq -r '.access_token')

if $debug; then echo "veeamBearer: $veeamBearer"; echo ""; fi

##
# Veeam Backup for Microsoft 365 Version. This part will check the Veeam Backup for Microsoft 365 version
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/ServiceInstance"
veeamVersionUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)
    
    veeamVersion=$(echo "$veeamVersionUrl" | jq --raw-output ".version")
	veeamDataload="veeam_office365_version,veeamVersion=$veeamVersion,veeamServer=$veeamRestServer v=1"
    if $debug; then echo "Dataload to write: $veeamDataload"; fi
    curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"


##
# Veeam Backup for Microsoft 365 Organization. This part will check on our Organization and retrieve Licensing Information
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/Organizations"
veeamOrgUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

declare -i arrayorg=0
for id in $(echo "$veeamOrgUrl" | jq -r '.[].id'); do
    veeamOrgId=$(echo "$veeamOrgUrl" | jq --raw-output ".[$arrayorg].id")
    veeamOrgName=$(echo "$veeamOrgUrl" | jq --raw-output ".[$arrayorg].name" | awk '{gsub(/ /,"\\ ");print}')

    ## Licensing
    veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/Organizations/$veeamOrgId/LicensingInformation"
    veeamLicenseUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)
    licensedUsers=$(echo "$veeamLicenseUrl" | jq --raw-output '.licensedUsers')
    newUsers=$(echo "$veeamLicenseUrl" | jq --raw-output '.newUsers')
    
	veeamDataload="veeam_office365_organization,veeamOrgName=$veeamOrgName licensedUsers=$licensedUsers,newUsers=$newUsers"
    if $debug; then echo "Dataload to write: $veeamDataload"; fi
    curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
    
    ##
    # Veeam Backup for Microsoft 365 Users. This part will check the total Users and if they are protected or not
    ##
    veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/LicensedUsers"
    veeamUsersUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)
    declare -i arrayLicensed=0
    for id in $(echo "$veeamUsersUrl" | jq -r '.results[].id'); do
    veeamUserId=$(echo "$veeamUsersUrl" | jq --raw-output ".results[$arrayLicensed].id")
    veeamUserName=$(echo "$veeamUsersUrl" | jq --raw-output ".results[$arrayLicensed].name" | awk '{gsub(/ /,"\\ ");print}')
    veeamUserBackup=$(echo "$veeamUsersUrl" | jq --raw-output ".results[$arrayLicensed].isBackedUp")   
      case $veeamUserBackup in
        "true")
            protectedUser="1"
        ;;
        "false")
            protectedUser="2"
        ;;
        esac
     veeamLicensedType=$(echo "$veeamUsersUrl" | jq --raw-output ".results[$arrayLicensed].licenseState")   
      case $veeamLicensedType in
        "Licensed")
            LicensedUser="1"
        ;;
        "Unlicensed")
            LicensedUser="2"
        ;;
        esac
    
    #echo "veeam_office365_overview_OD,veeamOrgName=$veeamOrgName,veeamUserName=$veeamUserName protectedUser=$protectedUser,licensedUser=$LicensedUser"
    veeamDataload="veeam_office365_overview_OD,veeamOrgName=$veeamOrgName,veeamUserName=$veeamUserName protectedUser=$protectedUser,licensedUser=$LicensedUser"
    if $debug; then echo "Dataload to write: $veeamDataload"; fi
    curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
	
    arrayLicensed=$arrayLicensed+1
    done

    arrayorg=$arrayorg+1
done
 

##
# Veeam Backup for Microsoft 365 Backup Repositories. This part will check the capacity and used space of the Backup Repositories
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/BackupRepositories"
veeamRepoUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

declare -i arrayrepo=0
for id in $(echo "$veeamRepoUrl" | jq -r '.[].id'); do
  repository=$(echo "$veeamRepoUrl" | jq --raw-output ".[$arrayrepo].name" | awk '{gsub(/ /,"\\ ");print}')
  capacity=$(echo "$veeamRepoUrl" | jq --raw-output ".[$arrayrepo].capacityBytes")
  freeSpace=$(echo "$veeamRepoUrl" | jq --raw-output ".[$arrayrepo].freeSpaceBytes")
  objectStorageId=$(echo "$veeamRepoUrl" | jq --raw-output ".[$arrayrepo].objectStorageId")
  objectStorageEncryptionEnabled=$(echo "$veeamRepoUrl" | jq --raw-output ".[$arrayrepo].objectStorageEncryptionEnabled")
  
  #echo "veeam_office365_repository,repository=$repository capacity=$capacity,freeSpace=$freeSpace"
  veeamDataload="veeam_office365_repository,repository=$repository capacity=$capacity,freeSpace=$freeSpace"
  if $debug; then echo "Dataload to write: $veeamDataload"; fi
  curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
  if [[ "$objectStorageId" == "null" ]]; then
        echo "It seems you are not using Object Storage offload on the Repository $repository, that's fine."
  else
  
  ##
  # Veeam Backup for Microsoft 365 Object Storage Repositories. This part will check the capacity and used space of the Object Storage Repositories
  ##
  veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/objectstoragerepositories/$objectStorageId"
  veeamObjectUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

        objectName=$(echo "$veeamObjectUrl" | jq --raw-output ".name" | awk '{gsub(/ /,"\\ ");print}')
        usedSpaceGB=$(echo "$veeamObjectUrl" | jq --raw-output ".usedSpaceBytes")
        type=$(echo "$veeamObjectUrl" | jq --raw-output ".type")
        # Bucket information
		case $type in
			AmazonS3|AmazonS3Glacier)
				bucketname=$(echo "$veeamObjectUrl" | jq --raw-output ".amazonBucketS3Aws.name" | awk '{gsub(/ /,"\\ ");print}')
				servicePoint="AWS"
				customRegionId=$(echo "$veeamObjectUrl" | jq --raw-output ".amazonBucketS3Aws.regionName" | awk '{gsub(/ /,"\\ ");print}')
			;;
			AmazonS3Compatible)
				bucketname=$(echo "$veeamObjectUrl" | jq --raw-output ".amazonBucketS3Compatible.name" | awk '{gsub(/ /,"\\ ");print}')
				servicePoint=$(echo "$veeamObjectUrl" | jq --raw-output ".amazonBucketS3Compatible.servicePoint" | awk '{gsub(/ /,"\\ ");print}')
				customRegionId=$(echo "$veeamObjectUrl" | jq --raw-output ".amazonBucketS3Compatible.customRegionId" | awk '{gsub(/ /,"\\ ");print}')
			;;
			AzureBlob|AzureBlobArchive)
				bucketname=$(echo "$veeamObjectUrl" | jq --raw-output ".azureContainer.name" | awk '{gsub(/ /,"\\ ");print}')
				servicePoint="Azure"
				customRegionId=$(echo "$veeamObjectUrl" | jq --raw-output ".azureContainer.regionType" | awk '{gsub(/ /,"\\ ");print}')
			;;
			*) 
		esac
		veeamDataload="veeam_office365_objectstorage,objectname=$objectName,type=$type,bucketname=$bucketname,servicePoint=$servicePoint,customRegionId=$customRegionId,objectStorageEncryptionEnabled=$objectStorageEncryptionEnabled usedSpaceGB=$usedSpaceGB"
		if $debug; then echo "Dataload to write: $veeamDataload"; fi
		curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
  
    fi
    arrayrepo=$arrayrepo+1
done


##
# Veeam Backup for Microsoft 365 Backup Proxies. This part will check the Name and Threads Number of the Backup Proxies
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/Proxies"
veeamProxyUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

declare -i arrayprox=0
for id in $(echo "$veeamProxyUrl" | jq -r '.[].id'); do
    hostName=$(echo "$veeamProxyUrl" | jq --raw-output ".[$arrayprox].hostName" | awk '{gsub(/ /,"\\ ");print}')
    threadsNumber=$(echo "$veeamProxyUrl" | jq --raw-output ".[$arrayprox].threadsNumber")
    status=$(echo "$veeamProxyUrl" | jq --raw-output ".[$arrayprox].status")
    
    #echo "veeam_office365_proxies,proxies=$hostName,status=$status threadsNumber=$threadsNumber"
    veeamDataload="veeam_office365_proxies,proxies=$hostName,status=$status threadsNumber=$threadsNumber"
	if $debug; then echo "Dataload to write: $veeamDataload"; fi
    curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
	
    arrayprox=$arrayprox+1
done

##
# Veeam Backup for Microsoft 365 Backup Jobs. This part will check the different Jobs, and the Job Sessions per every Job
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/Jobs"
veeamJobsUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

declare -i arrayJobs=0
for id in $(echo "$veeamJobsUrl" | jq -r '.[].id'); do
    nameJob=$(echo "$veeamJobsUrl" | jq --raw-output ".[$arrayJobs].name" | awk '{gsub(/ /,"\\ ");print}')
    idJob=$(echo "$veeamJobsUrl" | jq --raw-output ".[$arrayJobs].id")
    
    # Backup Job Sessions
    veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/Jobs/$idJob/JobSessions"
    veeamJobSessionsUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)
    declare -i arrayJobsSessions=0
    for id in $(echo "$veeamJobSessionsUrl" | jq -r '.results[].id'); do
      creationTime=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].creationTime")
      creationTimeUnix=$(date -d "$creationTime" +"%s")
      endTime=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].endTime")
      endTimeUnix=$(date -d "$endTime" +"%s")
      totalDuration=$(($endTimeUnix - $creationTimeUnix))
      status=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].status")
      case $status in
        Success)
            jobStatus="1"
        ;;
        Warning)
            jobStatus="2"
        ;;
        Failed)
            jobStatus="3"
        ;;
        esac
      processingRate=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].statistics.processingRateBytesPS")
      readRate=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].statistics.readRateBytesPS")
      writeRate=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].statistics.writeRateBytesPS")
      transferredData=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].statistics.transferredDataBytes")
      processedObjects=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].statistics.processedObjects")
      bottleneck=$(echo "$veeamJobSessionsUrl" | jq --raw-output ".results[$arrayJobsSessions].statistics.bottleneck")
      
      veeamDataload="veeam_office365_jobs,veeamjobname=$nameJob,bottleneck=$bottleneck totalDuration=$totalDuration,status=$jobStatus,processingRate=$processingRate,readRate=$readRate,writeRate=$writeRate,transferredData=$transferredData,processedObjects=$processedObjects $endTimeUnix"
	  if $debug; then echo "Dataload to write: $veeamDataload"; fi
	  curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
	  
    if [[ $arrayJobsSessions = "1000" ]]; then
        break
        else
            arrayJobsSessions=$arrayJobsSessions+1
    fi
    done
    arrayJobs=$arrayJobs+1
done

##
# Veeam Backup for Microsoft 365 Restore Sessions. This part will check the Number of Restore Sessions
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/RestoreSessions"
veeamRestoreSessionsUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

declare -i arrayRestoreSessions=0
for id in $(echo "$veeamRestoreSessionsUrl" | jq -r '.results[].id'); do
    name=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].name")
    #nameJob=$(echo $name | awk -F": " '{print $2}' | awk -F" - " '{print $1}' | awk '{gsub(/ /,"\\ ");print}')
	nameJob=$(echo $name | awk '{gsub(/ /,"\\ ");print}')
    organization=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].organization" | awk '{gsub(/ /,"\\ ");print}') 
    type=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].type")
    endTime=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].endTime")
    endTimeUnix=$(date -d "$endTime" +"%s")
    result=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].result")
    initiatedBy=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].initiatedBy")
    details=$(echo "$veeamRestoreSessionsUrl" | jq --raw-output ".results[$arrayRestoreSessions].details")
    itemsProcessed=$(echo $details | awk '//{ print $1 }')

    [[ ! -z "$itemsProcessed" ]] || itemsProcessed="0"
    itemsSuccess=$(echo $details | awk '//{ print $4 }' | awk '{gsub(/\(|\)/,"");print $1}')
    [[ ! -z "$itemsSuccess" ]] || itemsSuccess="0"

    veeamDataload="veeam_office365_restoresession,organization=$organization,veeamjobname=$nameJob,type=$type,result=$result,initiatedBy=$initiatedBy itemsProcessed=$itemsProcessed,itemsSuccess=$itemsSuccess $endTimeUnix"
	if $debug; then echo "Dataload to write: $veeamDataload"; fi
    curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"	
	
    arrayRestoreSessions=$arrayRestoreSessions+1
done

##
# Veeam Backup for Microsoft 365 Restore Portal. This part will check the if Restore Portal is enabled
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/RestorePortalSettings"
veeamRestorePortalUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

    restorePortalAppId=$(echo "$veeamRestorePortalUrl" | jq --raw-output ".applicationId")
    restorePortalEnabled=$(echo "$veeamRestorePortalUrl" | jq --raw-output ".isEnabled")
    case $restorePortalEnabled in
        false)
            restorePortal="1"
        ;;
        true)
            restorePortal="2"
        ;;
    esac

    veeamDataload="veeam_office365_restoreportal,organization=$organization,restorePortalAppId=$restorePortalAppId restorePortalEnabled=$restorePortal"
	if $debug; then echo "Dataload to write: $veeamDataload"; fi
    curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"

##
# Veeam Backup for Microsoft 365 RBAC Roles. This part will check the the RBAC Roles, and what privileges they have
##
veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/RbacRoles"
veeamRbacRoleUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

declare -i arrayRbacRoles=0
for id in $(echo "$veeamRbacRoleUrl" | jq -r '.[].id'); do
    rbacRoleId=$(echo "$veeamRbacRoleUrl" | jq --raw-output ".[$arrayRbacRoles].id")
    rbacRoleName=$(echo "$veeamRbacRoleUrl" | jq --raw-output ".[$arrayRbacRoles].name" | awk '{gsub(/ /,"\\ ");print}')
    rbacRoleDescription=$(echo "$veeamRbacRoleUrl" | jq --raw-output ".[$arrayRbacRoles].description" | awk '{gsub(/ /,"\\ ");print}')
    rbacRoleType=$(echo "$veeamRbacRoleUrl" | jq --raw-output ".[$arrayRbacRoles].roleType" | awk '{gsub(/ /,"\\ ");print}')

    ## Check the RBAC Restore Operators
    veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/RbacRoles/$rbacRoleId/operators"
    veeamRbacRoleOperatorUrl=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)

    declare -i arrayRbacRolesOperators=0
    for id in $(echo "$veeamRbacRoleOperatorUrl" | jq -r '.[].type'); do
        rbacRoleScopeType=$(echo "$veeamRbacRoleOperatorUrl" | jq --raw-output ".[$arrayRbacRolesOperators].type")

        case $rbacRoleScopeType in
        User)
            rbacROName=$(echo "$veeamRbacRoleOperatorUrl" | jq --raw-output ".[$arrayRbacRolesOperators].user.displayName" | awk '{gsub(/ /,"\\ ");print}')
            rbacRO365Name=$(echo "$veeamRbacRoleOperatorUrl" | jq --raw-output ".[$arrayRbacRolesOperators].user.name" | awk '{gsub(/ /,"\\ ");print}')
			
            veeamDataload="veeam_office365_rbac_operators,organization=$organization,rbacRoleName=$rbacRoleName,type=User,rbacROName=$rbacROName,rbacRO365Name=$rbacRO365Name rbacRoleAdminId=$arrayRbacRolesOperators"
			if $debug; then echo "Dataload to write: $veeamDataload"; fi
			curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
        ;;
        Group)
            rbacROName=$(echo "$veeamRbacRoleOperatorUrl" | jq --raw-output ".[$arrayRbacRolesOperators].group.displayName" | awk '{gsub(/ /,"\\ ");print}')
            rbacRO365Name=$(echo "$veeamRbacRoleOperatorUrl" | jq --raw-output ".[$arrayRbacRolesOperators].group.name" | awk '{gsub(/ /,"\\ ");print}')
            rbacRO365Type=$(echo "$veeamRbacRoleOperatorUrl" | jq --raw-output ".[$arrayRbacRolesOperators].group.type")
            
            veeamDataload="veeam_office365_rbac_operators,organization=$organization,rbacRoleName=$rbacRoleName,type=$rbacRO365Type,rbacROName=$rbacROName,rbacRO365Name=$rbacRO365Name rbacRoleAdminId=$arrayRbacRolesOperators"
			if $debug; then echo "Dataload to write: $veeamDataload"; fi
			curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"			
        ;;
        esac
        arrayRbacRolesOperators=$arrayRbacRolesOperators+1
    done

    ## Check the RBAC Selected Items per Role
    veeamVBOUrl="$veeamRestServer:$veeamRestPort/v6/RbacRoles/$rbacRoleId/selectedItems"
    veeamRbacRoleUrlScope=$(curl -X GET --header "Accept:application/json" --header "Authorization:Bearer $veeamBearer" "$veeamVBOUrl" 2>&1 -k --silent)
    
    declare -i arrayRbacRolesScope=0
    for id in $(echo "$veeamRbacRoleUrlScope" | jq -r '.[].type'); do
        rbacRoleScopeType=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].type")

        case $rbacRoleScopeType in
        User)
            rbacRoleScopeName=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].user.displayName" | awk '{gsub(/ /,"\\ ");print}')
            rbacRoleScope365Name=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].user.name" | awk '{gsub(/ /,"\\ ");print}')
            
			veeamDataload="veeam_office365_rbac_scope,organization=$organization,rbacRoleName=$rbacRoleName,type=User,rbacRoleScopeName=$rbacRoleScopeName,rbacRoleScope365Name=$rbacRoleScope365Name rbacRoleScopeId=$arrayRbacRoles"
			if $debug; then echo "Dataload to write: $veeamDataload"; fi
			curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"			
			
        ;;
        Group)
            rbacRoleScopeName=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].group.displayName" | awk '{gsub(/ /,"\\ ");print}')
            rbacRoleScope365Name=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].group.name" | awk '{gsub(/ /,"\\ ");print}')
            rbacRoleScope365Type=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].group.type")

            veeamDataload="veeam_office365_rbac_scope,organization=$organization,rbacRoleName=$rbacRoleName,type=$rbacRoleScope365Type,rbacRoleScopeName=$rbacRoleScopeName,rbacRoleScope365Name=$rbacRoleScope365Name rbacRoleScopeId=$arrayRbacRoles"
			if $debug; then echo "Dataload to write: $veeamDataload"; fi
			curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"			
			
        ;;
        Site)
            rbacRoleScopeName=$(echo "$veeamRbacRoleUrlScope" | jq --raw-output ".[$arrayRbacRolesScope].site.title" | awk '{gsub(/ /,"\\ ");print}')
            
			veeamDataload="veeam_office365_rbac_scope,organization=$organization,rbacRoleName=$rbacRoleName,type=Site,rbacRoleScopeName=$rbacRoleScopeName,rbacRoleScope365Name=$rbacRoleScopeName rbacRoleScopeId=$arrayRbacRoles"
			if $debug; then echo "Dataload to write: $veeamDataload"; fi
			curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
			
        ;;
        esac
        arrayRbacRolesScope=$arrayRbacRolesScope+1
    done
    
	veeamDataload="veeam_office365_rbac_roles,organization=$organization,rbacRoleId=$rbacRoleId,rbacRoleName=$rbacRoleName,rbacRoleDescription=$rbacRoleDescription,rbacRoleType=$rbacRoleType rbacRoleAdminId=$arrayRbacRoles"
 	if $debug; then echo "Dataload to write: $veeamDataload"; fi
	curl -i -XPOST "$veeamInfluxPostURL" -H "$veeamInfludPostAuth" --data-binary "$veeamDataload"
	
	arrayRbacRoles=$arrayRbacRoles+1
done
