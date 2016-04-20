function Check-GroupMembership {

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

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string]$ou = '<ADD DEFAULT OU>',

        # Param2 help description
        [Parameter(Mandatory=$false)]
        [string]$exemptGroup =  '<ADD DEFAULT EXEMPT GROUP>'
    )

            
## allow logon 8am - 6pm Monday to Friday            
[byte[]]$Officehours = @(0,0,0,0,255,3,0,255,3,0,255,3,0,255,3,0,255,3,0,0,0)
[byte[]]$Allhours = @(255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255)             
            
$restrictedUsers = Get-ADUser -Filter * -SearchBase $ou -Properties memberof
$exemptUsers = Get-ADGroupMember -Identity $exemptGroup

ForEach ($user in $restrictedUsers){
    if (Check-GroupMembership -user $user -group $exemptGroup){
        Set-ADUser $user -Replace @{logonhours = $Allhours}
        Write-Verbose "User $user is a member of the exemptGroup $exemptGroup and has no restrictions"
    } else {
        Set-ADUser $user -Replace @{logonhours = $Officehours}
        Write-Verbose "$user loginhours have been restricted to $hours"  
        }
    }
}