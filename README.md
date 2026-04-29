The CA deployment script will deploy the default policies in Report Only mode.
Within the script, there are two variables which need to be configured, these are for the Break Glass accounts, and the object id of a standard users group (something like All Company)

**$BreakGlassUPNs = @(
     ""
)**

In this section, enter the UPN or Object ID of the first Break Glass account.  Additional accounts can be added by editing the section to look like this:

**$BreakGlassUPNs = @(
     "firstaccount",
     "secondaccount"
)**

The standard users group can be added via object id or UPN in this section.

**$StandardUsersGroupId = ""**
