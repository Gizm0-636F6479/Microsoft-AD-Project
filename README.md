# Active-Directory ReadMe
This repository serves as a personal knowledge base and learning log for mastering Active Directory (AD) concepts, exploitation, and defense techniques. The focus is on practical application within controlled lab environments, primarily using virtual machines through VMware and learning tracks through HTB.

#Active Directory Structure
<pre>
ExampleCorp.com (Domain)
├─── Built-in (Default Container)
├─── Computers (Default Container)
├─── Users (Default Container)
└─── Organizational Units (OUs - Custom Management Structure)
    ├─── Infrastructure
    │    ├─── Servers
    │    │    ├─── Production Servers
    │    │    └─── Test/Development Servers
    │    └─── Shared Assets
    │         ├─── Printers (Container)
    │         └─── Service Accounts (Container)
    ├─── Departments
    │    ├─── IT Services
    │    │    ├─── IT Support
    │    │    └─── Network Operations
    │    │    ├─── Users (Container)
    │    │    └─── Computers (Container)
    │    ├─── Finance
    │    │    ├─── Users (Container)
    │    │    └─── Computers (Container)
    │    └─── Sales & Marketing
    │         ├─── Users (Container)
    │         └─── Computers (Container)
    └─── USA (Geographical OU)
         ├─── HQ - Atlanta
         └─── West Coast Offices
</pre>
