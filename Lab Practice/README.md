### TASKS:
Attempt to complete the challenges on your own. If you get stuck, the Solutions dropdown below each task can help you. This reference on the Active Directory PowerShell module will be extremely helpful. As an introductory course on AD, we do not expect you to know everything about the topic and how to administer it. The Solutions below each task offer a step-by-step of how to complete the task. This section is provided to give you a taste of the daily tasks that AD administrators perform. Instead of providing the information to you in a static format, we have opted to provide it in a more hands-on manner.

### TASK 1: MANAGE USERS
Our first task of the day includes adding a few new-hire users into AD. We are just going to create them under the "inlanefreight.local" scope, drilling down into the "Corp > Employees > HQ-NYC > IT " folder structure for now. Once we create our other groups, we will move them into the new folders. You can utilize the Active Directory PowerShell module (New-ADUser), the Active Directory Users and Computers snap-in, or MMC to perform these actions.

### USERS TO ADD
**User:**
- Andromeda Cepheus
- Orion Starchaser
- Artemis Callisto

**Attributes:**
- full name
- email (first-initial.lastname@inlanefreight.local) ( ex. j.smith@inlanefreight.local )
- display name
- User must change password at next logon