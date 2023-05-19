## AD FS federated authentication process
The following process details how a user would authenticate to AWS using Active Directory and AD FS:
- The flow is initiated when a user browses to the AD FS sample site (https://Fully.Qualified.Domain.Name.Here/adfs/ls/IdpInitiatedSignOn.aspx) inside their domain. When you install AD FS, you get a new virtual directory named AD FS for your default website, which includes this page.
- The sign-on page authenticates the user against Active Directory. Depending on the user's browser, they might be prompted for their Active Directory username and password.
- The user's browser receives a SAML assertion in the form of an authentication response from AD FS.
- The user's browser posts the SAML assertion to the AWS sign-in endpoint for SAML (https://signin.aws.amazon.com/saml). Behind the scenes, sign-in uses the AssumeRoleWithSAML API to request temporary security credentials and then constructs a sign-in URL for the AWS Management Console.
- The user's browser receives the sign-in URL and is redirected to the console.

![image](https://github.com/ilnim/aws-federated/assets/115760354/f40f944e-8d3b-461e-b621-5358fddd36f3)

`You will need a Active Directory domain controller with a domain. The domain controller instance should be in a private subnet. There is also public subnet with an instance for network address translation (NAT) and an instance for connecting to internal hosts using Remote Desktop. The public subnet is referred to as a DMZ. Routing tables, subnets, and an internet gateway Active Directory. The following diagram shows the setup, including the AD FS instance that you will launch in the private subnet`

![image](https://github.com/ilnim/aws-federated/assets/115760354/b2b5da27-4abc-41d9-bcad-4be62da0682f)

`The NAT instance allows outbound internet access (e.g., for Windows Update or to reach IAM) for instances in the private subnet. The server instance should only allow inbound http traffic for accessing instances in the private subnet using remote desktop protocol (RDP).`

`To log in to your private subnet instances, you must open a browser and connect to the public-facing server instance via http. Then you can open an RDP connection from the server instance to the domain controller instance or AD FS instance in the private subnet using the private IP address. In this case, the server instance acts as a bastion (jump) host.`

### Connect to the domain controller instance
Because the domain controller and AD FS instances are in a private subnet, you must go through the server to connect to them.
- Open the http link to the server and sign in 
- When prompted to allow your PC to be discoverable on the network, select Yes. 
- Select Start , and type Active Dir.
- In the search results, select Active Directory Users and Computers

### Create a group to view EC2 instances in AWS 
- Right-click your domain, and select New > Group. 
- In the New Object - Group window, for Group name, enter AWS-View-EC2

`When working with AD FS and SAML, group names and user names in Active Directory and IAM are case-sensitive` 

- Select OK. 
- On the right side of the window, double-click your domain. 
- Right-click AWS-View-EC2, and select Properties. 
- Select the Members tab.
- Select Add. 
- For Enter the object names to select, enter Administrator 
- Select Check Names. 
- Select OK, and then select OK again to close the windows.

### Create a group to view S3 instances in AWS

`Now you will create a second group to see how you can restrict user AWS Management Console access using Active Directory. In a production environment, you would assign users to groups as appropriate; however, for this lab you will use a single user and put them in multiple groups so you can see the functionality.`
- At the top-left of the Active Directory Users and Computers window, select the left arrow icon to return to the domain level.
- Right-click your domain, and select New > Group. 
- In the New Object - Group window, for Group name, enter AWS-View-S3

`When working with AD FS and SAML, group names and user names in Active Directory and IAM are case-sensitive.` 

- Select OK. 
- On the right side of the window, double-click your domain. 
- Right-click AWS-View-S3, and select Properties.
- Select the Members tab. 
- Select Add. 
- For Enter the object names to select, enter Administrator 
- Select Check Names. 
- Select OK, and then select OK again to close the windows. Create a domain user Now you need to create a user that will be used later to configure AD FS.
- At the top-left of the Active Directory Users and Computers window, select the left arrow icon to return to your domain level.
- Right-click your domain, and select New > User. 
- In the New Object - User window, configure the following: • First name: Enter ADFSSVC • User logon name: Enter ADFSSVC

`When working with AD FS and SAML, group names and user names in Active Directory and IAM are case-sensitive`

- Select Next. 
- Uncheck the User must change password at next logon check box.

`If the User must change password at next logon is left enabled, the AD FS setup and some important future steps will fail. Ensure you uncheck this option.`

- For Password and Confirm password, enter Mypa$$word123 
- Select Next, and then select Finish. 

## Join your AD FS instance to the domain
First you wll add the domain controller's private IP to the TCP/IPv4 settings as a DNS server. Active Directory uses Domain Name System (DNS) name resolution services to make it possible for clients in the domain to locate domain controllers for directory services.

`Run the following command: C:\Windows\System32\control.exe ncpa.cpl`

- Right-click the Ethernet icon, and select Properties.
- In the Ethernet Properties window, select Internet Protocol Version 4 (TCP/IPv4), and then select Properties.
- Select Use the following DNS server addresses. 
- For Preferred DNS server, enter 10.0.0.10 
- Select OK. 
- Close the window. 
- Return to PowerShell and run the following command:

`ping mydomain.local`

This should resolve to 10.0.0.10, which is the IP address of the domain controller. 
- Open the System Properties window by running the following command in PowerShell: 

`systempropertiescomputername`

- Select Change.
From here, domain information will be configured to allow the AD FS to join the domain. 
- Configure the following: • Computer name: Enter adfsserver • Member of: Select Domain • Domain: yourdomain
- Select OK; Windows Security window appears requiring administrator authentication to process the action.
- Configure the following in the security window: • User name: Enter Administrator • Password: yourpassword
- In the restart notification pop-up box, select OK to confirm the that system will reboot after successfully joining the domain.
- Close any open windows. 
- The system will now prompt you to reboot the instance. Select Restart Now.
- A window will appear within the browser, indicating you have been disconnected from the RDP session. Select the logout option.

## Create a self-signed certificate on AD FS
- Connect to AD FS as the domain administrator.
- Select Start , and then select Server Manager. 

`It may take a few seconds for Server Manager to load completely.`

- If you see a windows that says, Try managing servers with Windows Admin Center, select the X to close the window.
- Select Add roles and features. 
- On the Before you begin page, select Next. 
- On the Select installation type page, select Next. 
- On the Select destination server page, select Next. 
- On the Select server roles page, select Web Server (IIS). A dialog box opens. 
- Select Add Features. 
- Select Next. 
- On the Select features page, select Next. 
- On the Web Server Role (IIS) page, select Next. 
- On the Select role services page, select Next. 
- On the Confirm installation selections page, select Install. 
- Wait for the installation to finish, and then select Close.
- At the top-right corner of the Server manaer dashboard, locate and select the drop down for Tools > Internet Information Services (IIS) Manager.
- In the left navigation pane, select ADFSSERVER. 
- Double-click Server Certificates. Note You may need to scroll down to see this icon. 
- In the Actions pane on the right, select Create Self-Signed Certificate. 
- Configure the following: • Specify a friendly name for the certificate: Enter adfs • Select a certificate store for the new certificate: Select Web Hosting 
- Select OK. 
- In the server certificates list, right-click the adfs certificate, and select Export. 
- Configure the following: • Export to: Enter C:\Users\administrator\Desktop\adfs.pfx • Password: Enter Mypa$$word123 • Confirm password: Enter Mypa$$word123 
- Select OK. 
- Close the Internet Information Services (IIS) Manager window.

## Install AD FS 
- In Server Manager, select Add roles and features. 
- On the Before you begin page, select Next. 
- On the Select installation type page, select Next. 
- On the Select destination server page, select Next. 
- On the Select server roles page, select Active Directory Federation Services. 
- Select Next. 
- On the Select features page, select Next. 
- On the Active Directory Federation Services (AD FS) page, select Next.
- On the Confirm installation selections page, select Restart the destination server automatically if required.
- When prompted to allow automatic restarts, select Yes. 
- Select Install.
- Wait for the installation to complete. Then, select the Configure the federation service on this server link.

`If you closed the window before selecting the link, open the next wizard by selecting the notification icon in the Server Manager menu bar.`

- On the Welcome page, make sure Create the first federation server in a federation server farm is selected. Then, select Next.
- On the Connect to Active Directory Domain Services page, verify that mydomain\administrator is listed.

`If mydomain\administrator is not listed, follow these steps: • Select Change • For User name, enter mydomain\administrator`

- For Password, enter the AdministratorPassword found on the left side of the lab instructions.
- Select OK 
- Select Next. 
- On the Specify Service Properties page, select Import.
- Locate the adfs.pfx certificate file that you created earlier and exported to the Desktop, and select Open.
- When prompted for the certificate password, enter Mypa$$word123 and select OK. This updates the SSL Certificate and Federation Service Name fields. 
- For Federation Service Display Name, enter AWSADFS 
- Select Next. 
- On the Specify Service Account page, select Select. 
- For Enter the object name to select, enter ADFSSVC 
- Select Check Names, and then select OK. 
- For Account Password, enter Mypa$$word123 
- Select Next. 
- On the Specify Configuration Database page, select Next. 
- On the Review Options page, review your options, and then select Next. 
- On the Pre-requisite Checks page, select Configure.

When the installation is finished, you may see an error message related to SPN configuration. This is a known issue that sometimes occurs with AD FS setup. If you receive the error, open PowerShell and run the following command:

`setspn -a host/localhost adfssvc`

This command registers the Service Principal Names. The success message should look like the following:

`Checking domain DC=mydomain,DC=local
Registering ServicePrincipalNames for CN=ADFSSVC,DC=mydomain,DC=local host/localhost
Updated object`

- In the AD FS Configuration Wizard, select Close. 
- Close the Server Manager window.
- Open PowerShell, and run the following commands separately to download the SAML metadata document for the AD FS instance:

`cd Desktop`

`wget https://adfsserver.mydomain.local/FederationMetadata/2007-06/FederationMetadata.xml -OutFile FederationMetadata.xml`

- Open the FederationMetadata.xml file that you just created using a text editor such as Notepad.
The FederationMetadata.xml is saved on the desktop.
- Copy the contents of the file to a text file on your personal desktop. 
- Save the text file as FederationMetadata.xml Next, you will upload the FederationMetadata.xml file to the AWS Management Console.

## Set up AWS IAM to work with AD FS
- In the AWS Management Console, at the top of the page, in the unified search bar, search for and choose IAM.
- In the left navigation pane, select Identity providers. 
- Select Add Provider. 
- Configure the following: • Provider Type: Select SAML Provider Name: Enter ADFS 
- Select Choose File. 
- Browse to and select the FederationMetadata.xml file that you saved earlier. 
- Select Add provider.

## Set up AWS as a trusted relying party
- Open Server Manager.
- In the left navigation pane, select Local Server.
- In the PROPERTIES section to the right, for IE Enhanced Security Configuration, select the On link.
- For both Administrators and Users, select Off, and then select OK. 
- Select Tools > AD FS Management. 
- In the Actions pane on the right, select Add Relying Party Trust.... Note You can also select Required: Add a trusted relying party in the Overview section. 
- On the Welcome page, select Start.
- On the Select Data Source page, confirm that Import data about the relying party published online or on a local network is selected.
- For Federation metadata address (host name or URL), enter https://signin.aws.amazon.com/static/saml-metadata.xml
- Select Next. 
- On the Specify Display Name page, select Next. 
- On the Choose Access Control Policy page, select Next. 
- On the Ready to Add Trust page, select Next. 
- On the Finish page, select Configure claims issuance policy for the application. 
- Select Close.

### Configure claim rules for the AWS relying party

`You will add and configure claim rules, which ensure that elements such as NameId, RoleSessionName, and Roles are added to the SAML authentication response. AWS requires these elements; AD FS does not provide them by default.`

- In the AD FS Management area of Server Manager, in the left navigation pane, select the Relying Party Trusts folder.
Note To access the AD FS Management area of Server Manager, select Tools > AD FS Management. The Tools menu is at the top-right corner of the Server Manager dashboard.
- In the Actions pane on the right, select Edit Claim Issuance Policy. 
- Select Add Rule. 
- For Claim rule template, select Transform an Incoming Claim. 
- Select Next. 
- On the Configure Claim Rule page, configure the following: • Claim rule name: Enter Name ID • Incoming claim type: Select Windows account name • Outgoing claim type: Select Name ID • Outgoing name ID format: Select Persistent Identifier 
- Select Finish. 
- Select Add Rule again. 
- For Claim rule template, select Send LDAP Attributes as Claims. 
- Select Next. 
- On the Configure Claim Rule page, configure the following: • Claim rule name: Enter RoleSessionName • Attribute store: Select Active Directory • LDAP Attribute: Select SAM-Account-Name • Outgoing Claim Type: Enter
https://aws.amazon.com/SAML/Attributes/RoleSessionName
- Select Finish. 
- Select Add Rule for the third time.
- For Claim rule template, select Send Claims Using a Custom Rule. 
- Select Next. 
- On the Configure Claim Rule page, configure the following: • Claim rule name: Enter Get AD Groups • Custom rule: Copy and paste the following: 
 
`c:[Type ==
"http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("http://temp/variable"), query = ";tokenGroups;{0}", param = c.Value);`

This rule uses the standard Active Directory schema to identify user groups from Active Directory and pass them to IAM.

- Select Finish. Note Leave the Edit Claim Issuance Policy window open.
- In the AWS Management Console, at the top of the page, in the unified search bar, search for and choose IAM.
- In the left navigation pane, select Identity providers. 
- Select the Provider Name for the ADFS provider. Note Select the Provider Name, not the checkbox next to the provider. 
- Copy the Provider ARN value and save it to use later.

`The value should look similar to the following: arn:aws:iam::999999999999:saml-provider/ADFS`

- In the left navigation pane, select Roles. 
- Select the Role name for the AWS-View-EC2 role. 
- Copy the Role ARN value and save it to use later.

`The value should look similar to the following: arn:aws:iam::999999999999:role/AWS-View-EC2`
- In your text editor, delete the word View-EC2 from the end of the role ARN. 
 
`The value should now look similar to the following: arn:aws:iam::036275514250:role/AWS-
- Return to the RDP session of your AD FS instance. 
- In the Edit Claim Issuance Policy window, select Add Rule.
- For Claim rule template, select Send Claims Using a Custom Rule. 
- Select Next. 
- On the Configure Claim Rule page, configure the following: • Claim rule name: Enter Roles • Custom rule: Copy and paste the following:

`c:[Type == "http://temp/variable", Value =~ "(?i)^AWS-"] => issue(Type = "https://aws.amazon.com/SAML/Attributes/Role", Value = RegExReplace(c.Value, "AWS-", "SAMLARN,ROLEARN"));`

- In the pasted text, replace SAMLARN with the provider ARN value you saved earlier. Replace ROLEARN with the role ARN value that you saved earlier.

`Check that you have removed the word View-EC2 from the end of the role ARN.`

The custom rule text should now look similar to the following:

`c:[Type == "http://temp/variable", Value =~ "(?i)^AWS-"] => issue(Type = "https://aws.amazon.com/SAML/Attributes/Role", Value = RegExReplace(c.Value, "AWS-", "arn:aws:iam::036275514250:saml-provider/ADFS,arn:aws:iam::036275514250:role/AWS-"));`
- Select Finish, and then select OK.
- Close the AD FS Management window, and close Server Manager. 
- On the AD FS instance desktop, open PowerShell and run the following command: 
 
`Set-AdfsProperties -EnableIdpInitiatedSignonPage $true`

## Test the configuration by logging into AWS 
- On your AD FS instance, open Google Chrome.
- You may use any browser; however, you may need to change security configuration settings based on the browser type. 
- Copy and paste the following URL in the address bar: https://localhost/adfs/ls/IdpInitiatedSignOn.aspx

`If prompted that the connection is not private, select Advanced, and then select Proceed to localhost (unsafe).`

- Select Sign in to one of the following sites, and then select Sign in. 
- Enter the following values on the login page: • User name: Enter mydomain\Administrator • Password: Enter the value of AdministratorPassword from the left side of the lab page 
- Select AWS-View-EC2, and select Sign In.

`You are now signed in to the AWS Management Console as AWS-View-EC2/Administrator.`

- In the AWS Management Console, at the top of the page, in the unified search bar, search for and choose EC2.
- In the left navigation, select Instances.

You should see three instances listed. This is because the role you assumed has read access to EC2.

`If you do not see any resource information on the EC2 Dashboard, check the Region. Make sure the Region you are using on the console within the RDP session matches the Region in the console on your local computer.`

- In the AWS Management Console, at the top of the page, in the unified search bar, search for and choose S3.
Since you logged in with a role that only allows you to view EC2 information, you are denied access to view any information about Amazon S3.
- Return to the localhost AD FS login page by copying and pasting the following URL in the address bar:
https://localhost/adfs/ls/IdpInitiatedSignOn.aspx 
- Select Sign in. 
- Select AWS-View-S3, and select Sign In.
- In the AWS Management Console, at the top of the page, in the unified search bar, search for and choose EC2.
- In the left navigation, select Instances.
 
You should see a warning indicating You are not authorized to perform this operation. This is because the role you signed in with does not have permission to use EC2.

- In the AWS Management Console, at the top of the page, in the unified search bar, search for and choose S3.

You should see several buckets listed. 
