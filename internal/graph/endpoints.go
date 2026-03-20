package graph

// Microsoft Graph API base URLs and endpoint constants.
const (
	GraphBaseV1   = "https://graph.microsoft.com/v1.0"
	GraphBaseBeta = "https://graph.microsoft.com/beta"

	// Auth
	LoginBase = "https://login.microsoftonline.com"

	// Recon
	EndpointOrganization    = "/organization"
	EndpointAuthPolicy      = "/policies/authorizationPolicy"
	EndpointSubscribedSkus  = "/subscribedSkus"
	EndpointUsers           = "/users"
	EndpointGroups          = "/groups"
	EndpointGroupMembers    = "/groups/%s/members"
	EndpointApplications    = "/applications"
	EndpointServicePrincs   = "/servicePrincipals"
	EndpointOAuth2Grants    = "/oauth2PermissionGrants"
	EndpointRoleAssignments = "/roleManagement/directory/roleAssignments"
	EndpointRoleDefinitions = "/roleManagement/directory/roleDefinitions"
	EndpointCAPs            = "/identity/conditionalAccess/policies"
	EndpointSearchQuery     = "/search/query"
	EndpointUserInbox       = "/users/%s/mailFolders/Inbox/messages"
	EndpointUserAuthMethods = "/users/%s/authentication/methods"

	// Persistence
	EndpointAppAddPassword = "/applications/%s/addPassword"
	EndpointInvitations    = "/invitations"
	EndpointGroupMemberRef = "/groups/%s/members/$ref"

	// Pillage
	EndpointMeMessages    = "/me/messages"
	EndpointMeChats       = "/me/chats"
	EndpointChatMessages  = "/chats/%s/messages"
	EndpointDriveItem     = "/drives/%s/items/%s/content"
	EndpointUserMailbox   = "/users/%s/messages"

	// Cleanup
	EndpointDeleteApp         = "/applications/%s"
	EndpointDeleteGroup       = "/groups/%s"
	EndpointRemoveGroupMember = "/groups/%s/members/%s/$ref"

	// SharePoint Sites
	EndpointSites           = "/sites"
	EndpointSiteByID        = "/sites/%s"
	EndpointSiteLists       = "/sites/%s/lists"
	EndpointSiteDrives      = "/sites/%s/drives"
	EndpointSitePermissions = "/sites/%s/permissions"
	EndpointSiteRoot        = "/sites/root"
	EndpointAllSites        = "/sites/getAllSites" // admin: requires Sites.Read.All application permission

	// M365 Group → SharePoint site
	EndpointGroupSiteRoot = "/groups/%s/sites/root"

	// Estimate access (beta)
	EndpointEstimateAccess = "/roleManagement/directory/estimateAccess"

	// Domains
	EndpointDomains = "/domains"

	// Devices
	EndpointDevices = "/devices"

	// OneNote
	EndpointMeNotebooks   = "/me/onenote/notebooks"
	EndpointMeSections    = "/me/onenote/sections"
	EndpointMePages       = "/me/onenote/pages"
	EndpointMePageContent = "/me/onenote/pages/%s/content"

	EndpointUserNotebooks   = "/users/%s/onenote/notebooks"
	EndpointUserSections    = "/users/%s/onenote/sections"
	EndpointUserPages       = "/users/%s/onenote/pages"
	EndpointUserPageContent = "/users/%s/onenote/pages/%s/content"

	// Calendar
	EndpointMeEvents   = "/me/events"
	EndpointUserEvents = "/users/%s/events"

	// Me
	EndpointMe = "/me"
)
