function _CheckGroupMembership {

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Provide the User CN you wish to check for group membership
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $user,

        # Provide the Group CN you wish to check the user is a member of
        [Parameter(Mandatory=$true)]
        [string]$group
    )

if ($user.memberof -like "$group"){
        $true
    } else {
        $false
        }
}


function Set-LogonHourRestrictions {
#Requires -modules ActiveDirectory

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Provide the CN of the OU you wish to apply logon hour restrictions to
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string]$OU = '<ADD DEFAULT OU>',

        # Provide the CN of the Group you wish to exempt from any restriction
        [Parameter(Mandatory=$false)]
        [string]$ExemptGroup =  '<ADD DEFAULT EXEMPT GROUP>'
    )

            
# allow logon 8am - 6pm Monday to Friday            
[byte[]]$Officehours = @(0,0,0,0,255,3,0,255,3,0,255,3,0,255,3,0,255,3,0,0,0)

# allow logon at all hours for exempt users
[byte[]]$Allhours = @(255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255)             
            
$restrictedUsers = Get-ADUser -Filter * -SearchBase $ou -Properties memberof
$exemptUsers = Get-ADGroupMember -Identity $exemptGroup

ForEach ($user in $restrictedUsers){
    if (_CheckGroupMembership -user $user -group $exemptGroup){
        Set-ADUser $user -Replace @{logonhours = $Allhours}
        Write-Verbose "User $user is a member of the exemptGroup $exemptGroup and has no restrictions"
    } else {
        Set-ADUser $user -Replace @{logonhours = $Officehours}
        Write-Verbose "$user loginhours have been restricted to $hours"  
        }
    }
}